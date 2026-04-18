// cache_sharing.go implements cross-provider cache sharing for AI responses.
// By generating provider-agnostic cache keys from prompts, the same prompt
// sent to different providers can share cached responses, reducing API costs.
package ai

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
)

// SharedCacheKey generates a provider-agnostic cache key from a prompt.
// The same prompt sent to different providers produces the same key.
// Messages are hashed in order to produce a deterministic key.
func SharedCacheKey(messages []json.RawMessage) string {
	h := sha256.New()
	for _, msg := range messages {
		h.Write(msg)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// SharedCache stores provider-agnostic responses keyed by prompt hash.
// It uses a simple map with a maximum entry limit. When the limit is reached,
// the oldest entry is evicted (approximated by removing the first key found).
type SharedCache struct {
	mu         sync.RWMutex
	store      map[string][]byte // cache key -> response body
	maxEntries int
}

// NewSharedCache creates a new shared cache with the given maximum entry count.
func NewSharedCache(maxEntries int) *SharedCache {
	if maxEntries <= 0 {
		maxEntries = 1000
	}
	return &SharedCache{
		store:      make(map[string][]byte),
		maxEntries: maxEntries,
	}
}

// Get retrieves a cached response by key. Returns the response and true if
// found, nil and false otherwise.
func (c *SharedCache) Get(key string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	val, ok := c.store[key]
	if !ok {
		return nil, false
	}

	// Return a copy to prevent mutation.
	result := make([]byte, len(val))
	copy(result, val)
	return result, true
}

// Set stores a response in the cache. If the cache is full, one existing
// entry is evicted to make room.
func (c *SharedCache) Set(key string, response []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If key already exists, just update it.
	if _, exists := c.store[key]; exists {
		stored := make([]byte, len(response))
		copy(stored, response)
		c.store[key] = stored
		return
	}

	// Evict one entry if at capacity.
	if len(c.store) >= c.maxEntries {
		for k := range c.store {
			delete(c.store, k)
			break
		}
	}

	stored := make([]byte, len(response))
	copy(stored, response)
	c.store[key] = stored
}

// Size returns the number of entries in the cache.
func (c *SharedCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.store)
}

// Delete removes a specific entry from the cache.
func (c *SharedCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.store, key)
}

// Clear removes all entries from the cache.
func (c *SharedCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store = make(map[string][]byte)
}
