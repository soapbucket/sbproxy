// idempotency.go provides request-level deduplication using client-supplied
// idempotency keys.
//
// When a client sends a request with an idempotency key header (default
// "Idempotency-Key"), the cache is checked first. If a previous response
// exists and has not expired, the cached response is returned immediately
// without forwarding the request upstream. This prevents duplicate side
// effects from retried requests.
//
// Expired entries are cleaned up lazily on Get and periodically via
// CleanExpired.
package ai

import (
	"sync"
	"time"
)

const (
	defaultIdempotencyHeader = "Idempotency-Key"
	defaultIdempotencyTTL    = 300 // 5 minutes
)

// IdempotencyConfig configures request deduplication.
type IdempotencyConfig struct {
	Enabled bool   `json:"enabled,omitempty" yaml:"enabled"`
	Header  string `json:"header,omitempty" yaml:"header"`   // default "Idempotency-Key"
	TTLSecs int    `json:"ttl_secs,omitempty" yaml:"ttl_secs"` // default 300
}

// HeaderName returns the configured header name or the default.
func (c IdempotencyConfig) HeaderName() string {
	if c.Header != "" {
		return c.Header
	}
	return defaultIdempotencyHeader
}

// TTL returns the configured TTL or the default.
func (c IdempotencyConfig) TTL() time.Duration {
	if c.TTLSecs > 0 {
		return time.Duration(c.TTLSecs) * time.Second
	}
	return time.Duration(defaultIdempotencyTTL) * time.Second
}

// IdempotencyCache stores responses keyed by idempotency key.
type IdempotencyCache struct {
	mu      sync.RWMutex
	entries map[string]*idempotencyEntry
	ttl     time.Duration
}

type idempotencyEntry struct {
	response   []byte
	statusCode int
	headers    map[string]string
	expiresAt  time.Time
}

// NewIdempotencyCache creates a new cache with the given TTL.
// A zero or negative TTL defaults to 5 minutes.
func NewIdempotencyCache(ttl time.Duration) *IdempotencyCache {
	if ttl <= 0 {
		ttl = time.Duration(defaultIdempotencyTTL) * time.Second
	}
	return &IdempotencyCache{
		entries: make(map[string]*idempotencyEntry),
		ttl:     ttl,
	}
}

// Get returns a cached response if available and not expired.
// Expired entries are removed lazily on access.
func (c *IdempotencyCache) Get(key string) ([]byte, int, map[string]string, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		return nil, 0, nil, false
	}

	if time.Now().After(entry.expiresAt) {
		// Lazily remove expired entry
		c.mu.Lock()
		// Re-check under write lock to avoid double-delete races
		if e, exists := c.entries[key]; exists && time.Now().After(e.expiresAt) {
			delete(c.entries, key)
		}
		c.mu.Unlock()
		return nil, 0, nil, false
	}

	// Return a copy of headers to prevent mutation
	headersCopy := make(map[string]string, len(entry.headers))
	for k, v := range entry.headers {
		headersCopy[k] = v
	}

	return entry.response, entry.statusCode, headersCopy, true
}

// Set stores a response for the given key. If the key already exists,
// it is overwritten.
func (c *IdempotencyCache) Set(key string, response []byte, statusCode int, headers map[string]string) {
	headersCopy := make(map[string]string, len(headers))
	for k, v := range headers {
		headersCopy[k] = v
	}

	c.mu.Lock()
	c.entries[key] = &idempotencyEntry{
		response:   response,
		statusCode: statusCode,
		headers:    headersCopy,
		expiresAt:  time.Now().Add(c.ttl),
	}
	c.mu.Unlock()
}

// CleanExpired removes all expired entries. This should be called
// periodically (e.g., every minute) to prevent unbounded growth.
func (c *IdempotencyCache) CleanExpired() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
		}
	}
}

// Len returns the number of entries in the cache (including potentially expired ones).
func (c *IdempotencyCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
