// Package memorycache provides a simple in-memory implementation of plugin.ResponseCache.
package memorycache

import (
	"context"
	"sync"
	"time"
)

type entry struct {
	data      []byte
	expiresAt time.Time
}

// Cache is a simple in-memory response cache with TTL-based expiration and
// capacity-based eviction. It satisfies the plugin.ResponseCache interface.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]*entry
	maxSize int
}

// New creates a new in-memory cache. If maxSize is <= 0, it defaults to 1000.
func New(maxSize int) *Cache {
	if maxSize <= 0 {
		maxSize = 1000
	}
	return &Cache{
		entries: make(map[string]*entry),
		maxSize: maxSize,
	}
}

// Get retrieves a cached value by key. Returns (nil, false) on miss or expiry.
func (c *Cache) Get(_ context.Context, key string) ([]byte, bool) {
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expiresAt) {
		if ok {
			c.mu.Lock()
			delete(c.entries, key)
			c.mu.Unlock()
		}
		return nil, false
	}
	return e.data, true
}

// Set stores a value with the given TTL. Evicts the entry expiring soonest when
// the cache is at capacity.
func (c *Cache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxSize {
		if _, exists := c.entries[key]; !exists {
			var oldestKey string
			var oldestTime time.Time
			for k, v := range c.entries {
				if oldestKey == "" || v.expiresAt.Before(oldestTime) {
					oldestKey = k
					oldestTime = v.expiresAt
				}
			}
			delete(c.entries, oldestKey)
		}
	}
	c.entries[key] = &entry{
		data:      value,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

// Delete removes a cached entry by key.
func (c *Cache) Delete(_ context.Context, key string) error {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
	return nil
}
