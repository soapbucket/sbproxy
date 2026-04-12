// Package origincache provides per-origin key-value caching with LRU eviction,
// TTL expiration, AES-256-GCM encryption at rest, and origin-ID key namespacing.
package origincache

import (
	"container/list"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"time"
)

var (
	ErrKeyTooLarge   = errors.New("cache: key exceeds maximum size")
	ErrValueTooLarge = errors.New("cache: value exceeds maximum size")
	ErrCacheFull     = errors.New("cache: origin cache is full")
)

// entry is a single cache entry with TTL tracking.
type entry struct {
	key       string
	value     []byte // encrypted if cipher is set
	size      int64  // total size in bytes (key + value)
	expiresAt time.Time
	element   *list.Element // pointer into LRU list
}

// OriginCache is a per-origin key-value cache with LRU eviction, TTL, and optional AES-256-GCM encryption.
type OriginCache struct {
	mu       sync.RWMutex
	originID string
	cipher   cipher.AEAD // nil if no encryption key configured
	data     map[string]*entry
	lru      *list.List // front = most recently used
	config   CacheSystemConfig

	usedBytes int64
}

// NewOriginCache creates a new cache for the given origin.
func NewOriginCache(originID string, aeadCipher cipher.AEAD, config CacheSystemConfig) *OriginCache {
	config = config.withDefaults()
	return &OriginCache{
		originID: originID,
		cipher:   aeadCipher,
		data:     make(map[string]*entry),
		lru:      list.New(),
		config:   config,
	}
}

// Get retrieves a value from the cache. Returns nil, false if not found or expired.
func (c *OriginCache) Get(key string) ([]byte, bool) {
	fullKey := c.keyFor(key)

	c.mu.Lock()
	e, ok := c.data[fullKey]
	if !ok {
		c.mu.Unlock()
		return nil, false
	}

	// Check TTL expiry (lazy eviction)
	if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
		c.evictLocked(e)
		c.mu.Unlock()
		return nil, false
	}

	// Move to front of LRU
	c.lru.MoveToFront(e.element)
	val := e.value
	c.mu.Unlock()

	// Decrypt if needed
	if c.cipher != nil {
		decrypted, err := c.decrypt(val)
		if err != nil {
			return nil, false
		}
		return decrypted, true
	}

	return val, true
}

// Set stores a value in the cache with the given TTL. TTL of 0 uses the default TTL.
func (c *OriginCache) Set(key string, value []byte, ttl time.Duration) error {
	if len(key) > c.config.MaxKeySizeBytes {
		return ErrKeyTooLarge
	}
	if len(value) > c.config.MaxValueSizeBytes {
		return ErrValueTooLarge
	}

	// Clamp TTL
	if ttl <= 0 {
		ttl = c.config.DefaultTTL
	}
	if ttl > c.config.MaxTTL {
		ttl = c.config.MaxTTL
	}

	// Encrypt if needed
	stored := value
	if c.cipher != nil {
		var err error
		stored, err = c.encrypt(value)
		if err != nil {
			return err
		}
	}

	fullKey := c.keyFor(key)
	entrySize := int64(len(fullKey)) + int64(len(stored))
	maxBytes := int64(c.config.MaxSizePerOriginMB) * 1024 * 1024

	c.mu.Lock()
	defer c.mu.Unlock()

	// If key already exists, remove old entry first
	if old, ok := c.data[fullKey]; ok {
		c.evictLocked(old)
	}

	// Evict LRU entries until we have space
	for c.usedBytes+entrySize > maxBytes && c.lru.Len() > 0 {
		tail := c.lru.Back()
		if tail == nil {
			break
		}
		c.evictLocked(tail.Value.(*entry))
	}

	if c.usedBytes+entrySize > maxBytes {
		return ErrCacheFull
	}

	e := &entry{
		key:   fullKey,
		value: stored,
		size:  entrySize,
	}
	if ttl > 0 {
		e.expiresAt = time.Now().Add(ttl)
	}
	e.element = c.lru.PushFront(e)
	c.data[fullKey] = e
	c.usedBytes += entrySize

	return nil
}

// Delete removes a key from the cache.
func (c *OriginCache) Delete(key string) {
	fullKey := c.keyFor(key)

	c.mu.Lock()
	if e, ok := c.data[fullKey]; ok {
		c.evictLocked(e)
	}
	c.mu.Unlock()
}

// Len returns the number of entries in the cache (including expired but not yet evicted).
func (c *OriginCache) Len() int {
	c.mu.RLock()
	n := len(c.data)
	c.mu.RUnlock()
	return n
}

// UsedBytes returns the total bytes used by the cache.
func (c *OriginCache) UsedBytes() int64 {
	c.mu.RLock()
	n := c.usedBytes
	c.mu.RUnlock()
	return n
}

// EvictExpired removes all expired entries. Called periodically by CacheManager.
func (c *OriginCache) EvictExpired() int {
	now := time.Now()
	c.mu.Lock()
	count := 0
	for _, e := range c.data {
		if !e.expiresAt.IsZero() && now.After(e.expiresAt) {
			c.evictLocked(e)
			count++
		}
	}
	c.mu.Unlock()
	return count
}

// Clear removes all entries from the cache.
func (c *OriginCache) Clear() {
	c.mu.Lock()
	c.data = make(map[string]*entry)
	c.lru.Init()
	c.usedBytes = 0
	c.mu.Unlock()
}

// evictLocked removes an entry. Caller must hold c.mu write lock.
func (c *OriginCache) evictLocked(e *entry) {
	c.lru.Remove(e.element)
	delete(c.data, e.key)
	c.usedBytes -= e.size
}

// keyFor namespaces a key by origin ID.
func (c *OriginCache) keyFor(key string) string {
	return c.originID + ":" + key
}

func (c *OriginCache) encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.cipher.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return c.cipher.Seal(nonce, nonce, plaintext, nil), nil
}

func (c *OriginCache) decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := c.cipher.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("cache: ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return c.cipher.Open(nil, nonce, ct, nil)
}

// NewAEADCipher creates an AES-256-GCM cipher from a 32-byte key.
func NewAEADCipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
