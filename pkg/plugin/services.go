// services.go defines the ServiceProvider interface for shared runtime services.
package plugin

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

// ServiceProvider gives modules access to shared runtime services without
// requiring direct imports of internal packages. Modules receive this during
// Provision and use it to access storage, networking, caching, and observability.
// All methods must be safe for concurrent use.
type ServiceProvider interface {
	// --- Storage ---

	// KVStore returns the distributed key-value store (Redis, Pebble, etc.).
	// Returns nil when no distributed store is configured (standalone mode).
	KVStore() KVStore

	// Cache returns the object cache for general-purpose caching.
	// Returns nil when no cache backend is configured.
	Cache() CacheStore

	// --- Observability ---

	// Events returns the event emitter for publishing lifecycle events.
	// Always returns a valid emitter (no-op when no bus is configured).
	Events() EventEmitter
	Logger() *slog.Logger
	Metrics() Observer

	// --- Networking ---

	// TransportFor returns a shared, connection-pooled RoundTripper configured
	// per the given TransportConfig. Modules should use this instead of creating
	// their own http.Client to benefit from connection reuse and DNS caching.
	TransportFor(cfg TransportConfig) http.RoundTripper

	// --- Origin Resolution ---

	// ResolveOriginHandler looks up a compiled origin by hostname. Used by forward
	// rules and load balancers to delegate requests to other origins.
	ResolveOriginHandler(hostname string) (http.Handler, error)

	// ResolveEmbeddedOriginHandler compiles an inline origin definition on the fly.
	// Used by forward rules with embedded origin configs.
	ResolveEmbeddedOriginHandler(raw json.RawMessage) (http.Handler, error)

	// --- Caching ---
	ResponseCache() ResponseCache

	// --- Sessions ---
	Sessions() SessionProvider

	// --- Health ---
	// Health state persists across config reloads so that newly compiled handlers
	// inherit the last-known availability of their upstream targets.
	HealthStatus(target string) HealthState
	SetHealthStatus(target string, state HealthState)
}

// TransportConfig describes the desired behaviour of an HTTP transport.
// Modules pass this to ServiceProvider.TransportFor() to obtain a shared,
// connection-pooled http.RoundTripper instead of creating their own.
type TransportConfig struct {
	// InsecureSkipVerify disables TLS certificate verification.
	InsecureSkipVerify bool

	// Timeout is the maximum time for a single round-trip.
	Timeout time.Duration

	// MaxIdleConns limits idle connections in the pool.
	MaxIdleConns int
}

// HealthState records the current health of a target (upstream URL, origin hostname, etc.).
// It is stored by ServiceProvider and persists across config reloads so that
// newly compiled handlers inherit the last-known health of their backends.
type HealthState struct {
	// Healthy is true when the target is reachable.
	Healthy bool

	// Reason is a short human-readable explanation (e.g. "connection refused").
	Reason string

	// Since is the time at which this state was first observed.
	Since time.Time

	// ConsecutiveFailures tracks how many probes have failed in a row.
	ConsecutiveFailures int
}

// KVStore abstracts distributed state storage.
type KVStore interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Increment(ctx context.Context, key string, delta int64) (int64, error)
}

// EventEmitter abstracts event publishing.
type EventEmitter interface {
	Emit(ctx context.Context, event string, data map[string]any) error
	Enabled(event string) bool
}

// CacheStore abstracts a distributed object cache.
type CacheStore interface {
	Get(ctx context.Context, key string) (interface{}, bool)
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration)
}

// ResponseCache abstracts response-level caching for the proxy pipeline.
// Implementations may use in-memory LRU, Redis, or other backends.
type ResponseCache interface {
	Get(ctx context.Context, key string) ([]byte, bool)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
}

// SessionProvider abstracts session management for the proxy pipeline.
type SessionProvider interface {
	Encrypt(data string) (string, error)
	Decrypt(data string) (string, error)
	SessionStore() KVStore
}
