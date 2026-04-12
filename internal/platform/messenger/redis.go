// Package messenger provides a pluggable notification system for alerts and event delivery.
package messenger

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	maxReconnectRetries  = 10
	baseReconnectBackoff = 500 * time.Millisecond
	maxReconnectBackoff  = 30 * time.Second
)

// RedisMessenger represents a redis messenger.
type RedisMessenger struct {
	db      *redis.Client
	delay   time.Duration
	closers []io.Closer
	mu      sync.RWMutex
	topics  map[string]*redis.PubSub
	driver  string
}

// Send performs the send operation on the RedisMessenger.
func (r *RedisMessenger) Send(ctx context.Context, topic string, message *Message) error {
	return r.db.Publish(ctx, topic, message).Err()
}

// Subscribe performs the subscribe operation on the RedisMessenger.
func (r *RedisMessenger) Subscribe(ctx context.Context, topic string, callback func(context.Context, *Message) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	subscriber := r.db.Subscribe(ctx, topic)
	r.closers = append(r.closers, subscriber)
	r.topics[topic] = subscriber

	go r.subscribeLoop(ctx, topic, subscriber, callback)
	return nil
}

// subscribeLoop reads messages from the subscriber channel and reconnects
// with exponential backoff if the channel closes unexpectedly.
func (r *RedisMessenger) subscribeLoop(ctx context.Context, topic string, subscriber *redis.PubSub, callback func(context.Context, *Message) error) {
	defer func() {
		r.mu.Lock()
		for i, closer := range r.closers {
			if closer == subscriber {
				r.closers = append(r.closers[:i], r.closers[i+1:]...)
				break
			}
		}
		delete(r.topics, topic)
		r.mu.Unlock()
	}()

	for attempt := 0; ; attempt++ {
		var msg *Message

		for m := range subscriber.Channel() {
			// Reset attempt counter on successful message receipt
			attempt = 0

			if err := json.Unmarshal([]byte(m.Payload), &msg); err == nil {
				if err := callback(ctx, msg); err != nil {
					slog.Error("failed to call callback", "error", err)
				}
			} else {
				slog.Error("failed to unmarshal message", "error", err)
			}

			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(r.delay)
			}
		}

		// Channel closed. Check if context was cancelled (normal shutdown).
		select {
		case <-ctx.Done():
			slog.Debug("subscriber shutting down", "topic", topic)
			return
		default:
		}

		// Unexpected disconnect. Attempt reconnection with backoff.
		if attempt >= maxReconnectRetries {
			slog.Error("subscriber giving up after max reconnect attempts",
				"topic", topic, "attempts", attempt)
			return
		}

		backoff := baseReconnectBackoff * time.Duration(1<<attempt)
		if backoff > maxReconnectBackoff {
			backoff = maxReconnectBackoff
		}

		slog.Error("subscriber connection lost, reconnecting",
			"topic", topic, "attempt", attempt+1, "backoff", backoff)

		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}

		// Close old subscriber and create new one
		oldSubscriber := subscriber
		oldSubscriber.Close()
		subscriber = r.db.Subscribe(ctx, topic)

		r.mu.Lock()
		// Replace old subscriber reference in closers to avoid duplicates
		replaced := false
		for i, closer := range r.closers {
			if closer == oldSubscriber {
				r.closers[i] = subscriber
				replaced = true
				break
			}
		}
		if !replaced {
			r.closers = append(r.closers, subscriber)
		}
		r.topics[topic] = subscriber
		r.mu.Unlock()
	}
}

// Unsubscribe performs the unsubscribe operation on the RedisMessenger.
func (r *RedisMessenger) Unsubscribe(ctx context.Context, topic string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if subscriber, exists := r.topics[topic]; exists {
		subscriber.Close()
		delete(r.topics, topic)

		// Remove from closers
		for i, closer := range r.closers {
			if closer == subscriber {
				r.closers = append(r.closers[:i], r.closers[i+1:]...)
				break
			}
		}
	}
	return nil
}

// Close releases resources held by the RedisMessenger.
func (r *RedisMessenger) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, closer := range r.closers {
		if err := closer.Close(); err != nil {
			slog.Error("failed to close closer", "error", err)
		}
	}

	// Clear the slices and maps
	r.closers = nil
	r.topics = make(map[string]*redis.PubSub)

	return r.db.Close()
}

// Driver returns the driver name
func (r *RedisMessenger) Driver() string {
	return r.driver
}

// NewRedisMessenger creates and initializes a new RedisMessenger.
func NewRedisMessenger(settings Settings) (Messenger, error) {
	// Get DSN from params since we removed it from Settings
	dsn, ok := settings.Params["dsn"]
	if !ok {
		return nil, ErrInvalidConfiguration
	}

	options, err := redis.ParseURL(dsn)
	if err != nil {
		return nil, err
	}

	// Optimize connection pool for high throughput (per OPTIMIZATIONS.md #24)
	// Default values optimized for high-throughput scenarios
	options.PoolSize = getIntParam(settings.Params, "pool_size", 200)                // Max number of socket connections (increased from 100)
	options.MinIdleConns = getIntParam(settings.Params, "min_idle_conns", 20)      // Minimum number of idle connections (increased from 10)
	options.PoolTimeout = getDurationParam(settings.Params, "pool_timeout", 10*time.Second) // Amount of time client waits for connection (increased from 4s)

	// Performance tuning
	options.MaxRetries = getIntParam(settings.Params, "max_retries", 5) // Increased from 3
	options.MinRetryBackoff = 8 * time.Millisecond
	options.MaxRetryBackoff = 512 * time.Millisecond
	options.DialTimeout = 5 * time.Second
	options.ReadTimeout = getDurationParam(settings.Params, "read_timeout", 5*time.Second)   // Increased from 3s
	options.WriteTimeout = getDurationParam(settings.Params, "write_timeout", 5*time.Second)  // Increased from 3s

	delay := DefaultRedisDelay
	if delayStr, ok := settings.Params[ParamDelay]; ok {
		if parsedDelay, err := time.ParseDuration(delayStr); err == nil {
			delay = parsedDelay
		}
	}

	db := redis.NewClient(options)
	return &RedisMessenger{
		db:      db,
		delay:   delay,
		closers: []io.Closer{},
		topics:  make(map[string]*redis.PubSub),
		driver:  settings.Driver,
	}, nil
}

// getIntParam retrieves an integer parameter from settings, returning default if not found or invalid
func getIntParam(params map[string]string, key string, defaultValue int) int {
	if val, ok := params[key]; ok {
		if intVal, err := strconv.Atoi(val); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// getDurationParam retrieves a duration parameter from settings, returning default if not found or invalid
func getDurationParam(params map[string]string, key string, defaultValue time.Duration) time.Duration {
	if val, ok := params[key]; ok {
		if duration, err := time.ParseDuration(val); err == nil {
			return duration
		}
	}
	return defaultValue
}

func init() {
	Register(DriverRedis, NewRedisMessenger)
}
