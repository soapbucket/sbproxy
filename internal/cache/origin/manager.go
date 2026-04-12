// manager.go manages per-origin caches with global memory limits and optional encryption.
package origincache

import (
	"context"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// CacheManager manages per-origin caches and enforces global memory limits.
type CacheManager struct {
	mu     sync.RWMutex
	caches map[string]*OriginCache
	config CacheSystemConfig
	cipher cipher.AEAD // shared cipher for all origin caches, nil if no key
	stopCh chan struct{}
}

// NewCacheManager creates a new cache manager with the given system config.
func NewCacheManager(config CacheSystemConfig) (*CacheManager, error) {
	config = config.withDefaults()

	var aeadCipher cipher.AEAD
	if config.EncryptionKey != "" {
		key, err := base64.StdEncoding.DecodeString(config.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("cache: invalid encryption key: %w", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("cache: encryption key must be 32 bytes, got %d", len(key))
		}
		aeadCipher, err = NewAEADCipher(key)
		if err != nil {
			return nil, fmt.Errorf("cache: failed to create cipher: %w", err)
		}
	}

	m := &CacheManager{
		caches: make(map[string]*OriginCache),
		config: config,
		cipher: aeadCipher,
		stopCh: make(chan struct{}),
	}

	return m, nil
}

// GetOrCreate returns the cache for the given origin, creating it if needed.
func (m *CacheManager) GetOrCreate(originID string) *OriginCache {
	m.mu.RLock()
	if c, ok := m.caches[originID]; ok {
		m.mu.RUnlock()
		return c
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if c, ok := m.caches[originID]; ok {
		return c
	}

	c := NewOriginCache(originID, m.cipher, m.config)
	m.caches[originID] = c
	return c
}

// Release removes and clears the cache for the given origin.
func (m *CacheManager) Release(originID string) {
	m.mu.Lock()
	if c, ok := m.caches[originID]; ok {
		c.Clear()
		delete(m.caches, originID)
	}
	m.mu.Unlock()
}

// TotalUsedBytes returns the total bytes used across all origin caches.
func (m *CacheManager) TotalUsedBytes() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var total int64
	for _, c := range m.caches {
		total += c.UsedBytes()
	}
	return total
}

// EvictGlobal evicts LRU entries across all origins when global memory exceeds max_total_mb.
func (m *CacheManager) EvictGlobal() {
	maxTotal := int64(m.config.MaxTotalMB) * 1024 * 1024
	if maxTotal <= 0 {
		return
	}

	for m.TotalUsedBytes() > maxTotal {
		// Find the origin with the oldest LRU tail
		m.mu.RLock()
		var oldestCache *OriginCache
		var oldestTime time.Time
		for _, c := range m.caches {
			c.mu.RLock()
			if c.lru.Len() > 0 {
				tail := c.lru.Back()
				if tail != nil {
					e := tail.Value.(*entry)
					if oldestCache == nil || e.expiresAt.Before(oldestTime) {
						oldestCache = c
						oldestTime = e.expiresAt
					}
				}
			}
			c.mu.RUnlock()
		}
		m.mu.RUnlock()

		if oldestCache == nil {
			break
		}

		// Evict one entry from the oldest cache
		oldestCache.mu.Lock()
		if oldestCache.lru.Len() > 0 {
			tail := oldestCache.lru.Back()
			if tail != nil {
				oldestCache.evictLocked(tail.Value.(*entry))
			}
		}
		oldestCache.mu.Unlock()
	}
}

// StartSweeper starts a background goroutine that periodically evicts expired entries
// and enforces global memory limits.
func (m *CacheManager) StartSweeper(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-m.stopCh:
				return
			case <-ticker.C:
				m.mu.RLock()
				for _, c := range m.caches {
					evicted := c.EvictExpired()
					if evicted > 0 {
						slog.Debug("cache sweeper evicted expired entries",
							"origin_id", c.originID,
							"evicted", evicted,
						)
					}
				}
				m.mu.RUnlock()
				m.EvictGlobal()
			}
		}
	}()
}

// Stop stops the background sweeper.
func (m *CacheManager) Stop() {
	close(m.stopCh)
}

// CacheCount returns the number of active origin caches.
func (m *CacheManager) CacheCount() int {
	m.mu.RLock()
	n := len(m.caches)
	m.mu.RUnlock()
	return n
}
