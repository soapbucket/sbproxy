package callbacks

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

const (
	defaultBatchSize     = 50
	defaultFlushInterval = 5 * time.Second
)

// callbackEntry pairs a callback adapter with its configuration.
type callbackEntry struct {
	callback Callback
	config   *CallbackConfig
}

// CallbackManager collects callback payloads into an async queue and dispatches
// them in batches to all registered callback adapters.
type CallbackManager struct {
	callbacks     []callbackEntry
	queue         chan *CallbackPayload
	batchSize     int
	flushInterval time.Duration
	done          chan struct{}
	wg            sync.WaitGroup
	mu            sync.Mutex
}

// NewCallbackManager creates a manager with the given queue buffer size.
// Call Start() to begin processing and Stop() for graceful shutdown.
func NewCallbackManager(queueSize int) *CallbackManager {
	if queueSize <= 0 {
		queueSize = 1024
	}
	return &CallbackManager{
		queue:         make(chan *CallbackPayload, queueSize),
		batchSize:     defaultBatchSize,
		flushInterval: defaultFlushInterval,
		done:          make(chan struct{}),
	}
}

// Register adds a callback adapter with its configuration. Must be called before Start().
func (m *CallbackManager) Register(callback Callback, config *CallbackConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry := callbackEntry{callback: callback, config: config}
	m.callbacks = append(m.callbacks, entry)

	// Use per-adapter batch/flush settings if larger than current.
	if config.BatchSize > 0 && config.BatchSize < m.batchSize {
		m.batchSize = config.BatchSize
	}
	if config.FlushInterval > 0 && config.FlushInterval < m.flushInterval {
		m.flushInterval = config.FlushInterval
	}
}

// Emit enqueues a payload for async delivery. Non-blocking: drops the payload
// if the queue is full to avoid back-pressure on the request path.
func (m *CallbackManager) Emit(payload *CallbackPayload) {
	select {
	case m.queue <- payload:
	default:
		slog.Warn("callbacks: queue full, dropping payload", "request_id", payload.RequestID)
	}
}

// Start begins the background worker goroutine that batches and delivers payloads.
func (m *CallbackManager) Start() {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.worker()
	}()
}

// Stop signals the worker to drain remaining items and exit, then waits for completion.
func (m *CallbackManager) Stop() {
	close(m.done)
	m.wg.Wait()
}

// worker is the background loop that collects payloads and flushes in batches.
func (m *CallbackManager) worker() {
	batch := make([]*CallbackPayload, 0, m.batchSize)
	timer := time.NewTimer(m.flushInterval)
	defer timer.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		m.dispatch(batch)
		batch = make([]*CallbackPayload, 0, m.batchSize)
	}

	for {
		select {
		case payload := <-m.queue:
			batch = append(batch, payload)
			if len(batch) >= m.batchSize {
				flush()
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(m.flushInterval)
			}

		case <-timer.C:
			flush()
			timer.Reset(m.flushInterval)

		case <-m.done:
			// Drain remaining items from the queue.
			for {
				select {
				case payload := <-m.queue:
					batch = append(batch, payload)
				default:
					flush()
					return
				}
			}
		}
	}
}

// dispatch sends a batch of payloads to every registered callback, applying privacy redaction.
func (m *CallbackManager) dispatch(batch []*CallbackPayload) {
	m.mu.Lock()
	entries := make([]callbackEntry, len(m.callbacks))
	copy(entries, m.callbacks)
	m.mu.Unlock()

	for _, entry := range entries {
		if !entry.config.Enabled {
			continue
		}
		for _, payload := range batch {
			redacted := applyPrivacy(payload, entry.config.PrivacyMode)
			if err := entry.callback.Send(context.TODO(), redacted); err != nil {
				slog.Error("callbacks: send failed",
					"adapter", entry.callback.Name(),
					"request_id", payload.RequestID,
					"error", err,
				)
			}
		}
	}
}

// applyPrivacy returns a (possibly copied) payload with fields redacted
// according to the privacy mode.
//   - "full": no redaction, returns the original pointer.
//   - "metadata": messages are stripped.
//   - "minimal": messages and model are stripped.
//
// An empty or unrecognized mode defaults to "full".
func applyPrivacy(payload *CallbackPayload, mode string) *CallbackPayload {
	switch mode {
	case "metadata":
		cp := *payload
		cp.Messages = nil
		return &cp
	case "minimal":
		cp := *payload
		cp.Messages = nil
		cp.Model = ""
		return &cp
	default:
		return payload
	}
}
