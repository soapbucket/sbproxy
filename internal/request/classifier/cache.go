package classifier

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"
)

// EmbeddingCache is an LRU cache for embedding vectors keyed by SHA-256(text).
// It is safe for concurrent use.
type EmbeddingCache struct {
	entries map[string]*cacheEntry
	order   []string // ring buffer for LRU eviction order
	maxSize int
	ttl     time.Duration
	mu      sync.RWMutex
	hits    atomic.Int64
	misses  atomic.Int64
}

type cacheEntry struct {
	embedding []float32
	createdAt time.Time
}

// NewEmbeddingCache creates a cache with the given capacity and TTL.
func NewEmbeddingCache(maxSize int, ttl time.Duration) *EmbeddingCache {
	return &EmbeddingCache{
		entries: make(map[string]*cacheEntry, maxSize),
		order:   make([]string, 0, maxSize),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// Get retrieves a cached embedding. Returns nil, false on miss or expiry.
func (c *EmbeddingCache) Get(text string) ([]float32, bool) {
	key := hashKey(text)

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		c.misses.Add(1)
		return nil, false
	}

	if time.Since(entry.createdAt) > c.ttl {
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		c.misses.Add(1)
		return nil, false
	}

	c.hits.Add(1)
	return entry.embedding, true
}

// Put stores an embedding in the cache, evicting the oldest entry if at capacity.
func (c *EmbeddingCache) Put(text string, embedding []float32) {
	key := hashKey(text)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Already cached - update in place
	if _, ok := c.entries[key]; ok {
		c.entries[key] = &cacheEntry{
			embedding: embedding,
			createdAt: time.Now(),
		}
		return
	}

	// Evict oldest if at capacity
	if len(c.entries) >= c.maxSize && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}

	c.entries[key] = &cacheEntry{
		embedding: embedding,
		createdAt: time.Now(),
	}
	c.order = append(c.order, key)
}

// Stats returns cache hit/miss counters.
func (c *EmbeddingCache) Stats() (hits, misses int64) {
	return c.hits.Load(), c.misses.Load()
}

// Len returns the current number of cached entries.
func (c *EmbeddingCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

func hashKey(text string) string {
	h := sha256.Sum256([]byte(text))
	return hex.EncodeToString(h[:])
}
