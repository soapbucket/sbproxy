// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"time"
)

// PolicyStateStore provides an abstraction for policy state persistence.
// Implementations include in-memory (default) and Redis (distributed).
// All keys should be pre-namespaced by the caller (e.g. "policy:{workspace}:{type}:{key}").
type PolicyStateStore interface {
	// Get retrieves a value by key. Returns nil, nil if the key does not exist.
	Get(ctx context.Context, key string) ([]byte, error)

	// Set stores a value with an optional TTL. A zero TTL means no expiration.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error

	// Delete removes a key.
	Delete(ctx context.Context, key string) error

	// Increment atomically increments a counter and sets the TTL on first creation.
	// Returns the new counter value.
	Increment(ctx context.Context, key string, ttl time.Duration) (int64, error)

	// Keys returns all keys matching the given prefix. Implementations must use
	// cursor-based iteration (e.g. SCAN) rather than blocking commands (e.g. KEYS).
	Keys(ctx context.Context, prefix string) ([]string, error)
}
