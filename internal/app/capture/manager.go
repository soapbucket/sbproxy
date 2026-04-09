// Package capture records HTTP request/response pairs for debugging and replay.
package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
)

const (
	// exchangeTopicPrefix is the prefix for messenger topics.
	exchangeTopicPrefix = "exchanges:"

	// exchangeKeyPrefix is the prefix for cacher keys.
	exchangeKeyPrefix = "exchanges:"

	// defaultBufferSize is the default channel buffer size.
	// Increased significantly to handle high throughput after optimizations.
	defaultBufferSize = 65536

	// defaultWorkers is the default number of drain workers.
	// Increased to handle parallel processing of captured exchanges.
	defaultWorkers = 8
)

// Manager handles the lifecycle of traffic exchange capture.
// It provides non-blocking push, background draining to messenger/cacher,
// and retrieval from the cacher.
type Manager struct {
	messenger messenger.Messenger
	cacher    cacher.Cacher
	ch        chan *exchangeEnvelope
	pool      sync.Pool
	bufPool   sync.Pool
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup

	// Metrics
	captured atomic.Int64
	dropped  atomic.Int64
	errors   atomic.Int64

	// Rate-limited logging
	lastDroppedLog      atomic.Pointer[time.Time]
	droppedSinceLastLog atomic.Int64
}

// exchangeEnvelope wraps an exchange with routing metadata.
type exchangeEnvelope struct {
	hostname  string
	retention time.Duration
	exchange  *reqctx.Exchange
}

// Option configures the Manager.
type Option func(*Manager)

// WithBufferSize sets the channel buffer size.
func WithBufferSize(size int) Option {
	return func(m *Manager) {
		// Recreate channel with new size
		m.ch = make(chan *exchangeEnvelope, size)
	}
}

// NewManager creates a new capture Manager.
// It receives globally-configured messenger and cacher — no per-site storage config.
func NewManager(ctx context.Context, msg messenger.Messenger, cache cacher.Cacher, opts ...Option) *Manager {
	ctx, cancel := context.WithCancel(ctx)

	m := &Manager{
		messenger: msg,
		cacher:    cache,
		ch:        make(chan *exchangeEnvelope, defaultBufferSize),
		ctx:       ctx,
		cancel:    cancel,
	}

	// Exchange object pool to reduce GC pressure
	m.pool = sync.Pool{
		New: func() any {
			return &reqctx.Exchange{
				Meta: make(map[string]string, 4),
			}
		},
	}

	// Buffer pool for serialization
	m.bufPool = sync.Pool{
		New: func() any {
			return bytes.NewBuffer(make([]byte, 0, 4096))
		},
	}

	for _, opt := range opts {
		opt(m)
	}

	// Start drain workers
	for i := range defaultWorkers {
		m.wg.Add(1)
		go m.worker(i)
	}

	slog.Info("capture manager started",
		"buffer_size", cap(m.ch),
		"workers", defaultWorkers,
		"messenger_driver", msg.Driver(),
		"cacher_driver", cache.Driver())

	return m
}

// AcquireExchange gets an Exchange from the pool.
func (m *Manager) AcquireExchange() *reqctx.Exchange {
	ex := m.pool.Get().(*reqctx.Exchange)
	// Reset fields
	ex.ID = uuid.New().String()
	ex.Timestamp = time.Now()
	ex.Duration = 0
	ex.Request = reqctx.CapturedRequest{}
	ex.Response = reqctx.CapturedResponse{}
	// Clear meta map but keep allocation
	for k := range ex.Meta {
		delete(ex.Meta, k)
	}
	return ex
}

// ReleaseExchange returns an Exchange to the pool.
func (m *Manager) ReleaseExchange(ex *reqctx.Exchange) {
	// Clear body slices to allow GC of large bodies
	ex.Request.Body = nil
	ex.Request.Headers = nil
	ex.Response.Body = nil
	ex.Response.Headers = nil
	m.pool.Put(ex)
}

// Push enqueues an exchange for async processing.
// It is strictly non-blocking — if the buffer is full, the exchange is dropped
// and CaptureDropped metric is incremented.
func (m *Manager) Push(hostname string, exchange *reqctx.Exchange, retention time.Duration) {
	env := &exchangeEnvelope{
		hostname:  hostname,
		retention: retention,
		exchange:  exchange,
	}

	select {
	case m.ch <- env:
		m.captured.Add(1)
	default:
		// Buffer full — drop to prevent blocking the proxy
		m.dropped.Add(1)
		m.droppedSinceLastLog.Add(1)

		// Rate-limit logging to once every 5 seconds
		now := time.Now()
		lastLog := m.lastDroppedLog.Load()
		if lastLog == nil || now.Sub(*lastLog) > 5*time.Second {
			// Update last log time
			m.lastDroppedLog.Store(&now)
			
			// Reset counter and get value for logging
			count := m.droppedSinceLastLog.Swap(0)
			
			slog.Warn("capture buffer full, dropping exchanges",
				"hostname", hostname,
				"dropped_in_interval", count,
				"total_dropped", m.dropped.Load())
		}
		
		// Release the exchange back to the pool since we're dropping it
		m.ReleaseExchange(exchange)
	}
}

// worker drains the channel and persists exchanges.
func (m *Manager) worker(id int) {
	defer m.wg.Done()

	slog.Debug("capture worker started", "worker_id", id)

	for {
		select {
		case <-m.ctx.Done():
			// Drain remaining items before exit
			m.drainRemaining()
			slog.Debug("capture worker stopped", "worker_id", id)
			return
		case env := <-m.ch:
			if env == nil {
				continue
			}
			m.processExchange(env)
		}
	}
}

// drainRemaining processes any exchanges left in the channel on shutdown.
func (m *Manager) drainRemaining() {
	for {
		select {
		case env := <-m.ch:
			if env == nil {
				return
			}
			m.processExchange(env)
		default:
			return
		}
	}
}

// processExchange serializes and publishes/caches a single exchange.
func (m *Manager) processExchange(env *exchangeEnvelope) {
	// Serialize exchange to JSON
	buf := m.bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer m.bufPool.Put(buf)

	if err := json.NewEncoder(buf).Encode(env.exchange); err != nil {
		m.errors.Add(1)
		slog.Error("failed to serialize exchange",
			"hostname", env.hostname,
			"exchange_id", env.exchange.ID,
			"error", err)
		m.ReleaseExchange(env.exchange)
		return
	}

	data := buf.Bytes()

	ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
	defer cancel()

	// Publish to messenger for real-time SSE consumers
	topic := exchangeTopicPrefix + env.hostname
	msg := &messenger.Message{
		Body:    data,
		Channel: topic,
		Params: map[string]string{
			"exchange_id": env.exchange.ID,
			"hostname":    env.hostname,
		},
	}

	if err := m.messenger.Send(ctx, topic, msg); err != nil {
		// Log but don't fail — messenger may be noop
		slog.Debug("failed to publish exchange to messenger",
			"hostname", env.hostname,
			"exchange_id", env.exchange.ID,
			"error", err)
	}

	// Write to cacher for buffered retention
	namespace := exchangeKeyPrefix + env.hostname
	key := env.exchange.ID

	if err := m.cacher.PutWithExpires(ctx, namespace, key, bytes.NewReader(data), env.retention); err != nil {
		m.errors.Add(1)
		slog.Error("failed to cache exchange",
			"hostname", env.hostname,
			"exchange_id", env.exchange.ID,
			"error", err)
	}

	// Return exchange to pool after processing
	m.ReleaseExchange(env.exchange)
}

// ListOptions configures exchange listing.
type ListOptions struct {
	Limit  int
	Offset int
}

// List retrieves exchanges for a hostname from the cacher.
func (m *Manager) List(ctx context.Context, hostname string, opts ListOptions) ([]*reqctx.Exchange, error) {
	namespace := exchangeKeyPrefix + hostname

	// Use empty pattern to match all keys in the namespace.
	// The memory cacher uses prefix matching, so "*" would be treated as literal prefix.
	keys, err := m.cacher.ListKeys(ctx, namespace, "")
	if err != nil {
		return nil, fmt.Errorf("failed to list exchange keys: %w", err)
	}

	// Sort keys for consistent ordering (newest first by default since UUIDs are v4)
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))

	// Apply pagination
	if opts.Offset > 0 && opts.Offset < len(keys) {
		keys = keys[opts.Offset:]
	} else if opts.Offset >= len(keys) {
		return []*reqctx.Exchange{}, nil
	}

	if opts.Limit > 0 && opts.Limit < len(keys) {
		keys = keys[:opts.Limit]
	}

	exchanges := make([]*reqctx.Exchange, 0, len(keys))
	for _, key := range keys {
		reader, err := m.cacher.Get(ctx, namespace, key)
		if err != nil {
			slog.Debug("failed to get exchange from cache",
				"hostname", hostname,
				"key", key,
				"error", err)
			continue
		}

		var ex reqctx.Exchange
		if err := json.NewDecoder(reader).Decode(&ex); err != nil {
			slog.Debug("failed to decode cached exchange",
				"hostname", hostname,
				"key", key,
				"error", err)
			continue
		}

		exchanges = append(exchanges, &ex)
	}

	return exchanges, nil
}

// Get retrieves a single exchange by ID from the cacher.
func (m *Manager) Get(ctx context.Context, hostname, exchangeID string) (*reqctx.Exchange, error) {
	namespace := exchangeKeyPrefix + hostname

	reader, err := m.cacher.Get(ctx, namespace, exchangeID)
	if err != nil {
		return nil, fmt.Errorf("exchange not found: %w", err)
	}

	var ex reqctx.Exchange
	if err := json.NewDecoder(reader).Decode(&ex); err != nil {
		return nil, fmt.Errorf("failed to decode exchange: %w", err)
	}

	return &ex, nil
}

// Subscribe subscribes to real-time exchanges for a hostname via the messenger.
func (m *Manager) Subscribe(ctx context.Context, hostname string, handler func(context.Context, *reqctx.Exchange) error) error {
	topic := exchangeTopicPrefix + hostname

	return m.messenger.Subscribe(ctx, topic, func(ctx context.Context, msg *messenger.Message) error {
		var ex reqctx.Exchange
		if err := json.NewDecoder(strings.NewReader(string(msg.Body))).Decode(&ex); err != nil {
			slog.Debug("failed to decode exchange from messenger",
				"hostname", hostname,
				"error", err)
			return nil // Don't propagate decode errors
		}
		return handler(ctx, &ex)
	})
}

// Unsubscribe unsubscribes from real-time exchanges for a hostname.
func (m *Manager) Unsubscribe(ctx context.Context, hostname string) error {
	topic := exchangeTopicPrefix + hostname
	return m.messenger.Unsubscribe(ctx, topic)
}

// Metrics returns current capture metrics.
func (m *Manager) Metrics() reqctx.CaptureMetrics {
	return reqctx.CaptureMetrics{
		Captured: m.captured.Load(),
		Dropped:  m.dropped.Load(),
		Errors:   m.errors.Load(),
	}
}

// Close shuts down the manager and waits for workers to finish.
func (m *Manager) Close() error {
	m.cancel()
	m.wg.Wait()

	metrics := m.Metrics()
	slog.Info("capture manager stopped",
		"captured", metrics.Captured,
		"dropped", metrics.Dropped,
		"errors", metrics.Errors)

	return nil
}
