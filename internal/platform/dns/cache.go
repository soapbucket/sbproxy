// Package dns implements a DNS resolution cache to reduce lookup latency for upstream hosts.
package dns

import (
	"container/list"
	"context"
	"log/slog"
	"net"
	"sync"
	"time"
)

// CacheEntry represents a cached DNS entry
type CacheEntry struct {
	IPs        []net.IP
	ExpiresAt  time.Time
	StaleUntil time.Time // For stale-while-error support
	IsNegative bool      // True for NXDOMAIN responses
}

// IsExpired checks if the cache entry has expired
func (e *CacheEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// IsStale checks if the cache entry is stale but can still be served
func (e *CacheEntry) IsStale() bool {
	return time.Now().After(e.ExpiresAt) && time.Now().Before(e.StaleUntil)
}

// CacheConfig configures DNS cache behavior
type CacheConfig struct {
	Enabled           bool
	MaxEntries        int
	DefaultTTL        time.Duration
	NegativeTTL       time.Duration
	ServeStaleOnError bool
	BackgroundRefresh bool
}

// DefaultCacheConfig returns default DNS cache configuration
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		Enabled:           true,
		MaxEntries:        10000,
		DefaultTTL:        300 * time.Second,
		NegativeTTL:       60 * time.Second,
		ServeStaleOnError: true,
		BackgroundRefresh: true,
	}
}

// Cache implements an LRU DNS cache with TTL support
type Cache struct {
	config CacheConfig
	mu     sync.RWMutex
	cache  map[string]*CacheEntry
	order  *list.List               // Doubly-linked list for LRU eviction
	index  map[string]*list.Element // Map for O(1) element lookup
	stopCh chan struct{}            // Signals background goroutines to stop
}

// NewCache creates a new DNS cache with the given configuration
func NewCache(config CacheConfig) *Cache {
	if !config.Enabled {
		return nil
	}

	c := &Cache{
		config: config,
		cache:  make(map[string]*CacheEntry),
		order:  list.New(),
		index:  make(map[string]*list.Element),
		stopCh: make(chan struct{}),
	}

	// Start background refresh goroutine if enabled
	if config.BackgroundRefresh {
		go c.backgroundRefreshLoop()
	}

	return c
}

// Get retrieves a cached DNS entry
func (c *Cache) Get(hostname string) (*CacheEntry, bool) {
	if c == nil {
		return nil, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.cache[hostname]
	if !exists {
		return nil, false
	}

	// Check if expired
	if entry.IsExpired() {
		// Check if we can serve stale entry
		if c.config.ServeStaleOnError && entry.IsStale() {
			// Update LRU order even for stale entries (O(1))
			c.moveToFront(hostname)
			return entry, true
		}
		return nil, false
	}

	// Update LRU order on access (O(1))
	c.moveToFront(hostname)

	return entry, true
}

// Put stores a DNS entry in the cache
func (c *Cache) Put(hostname string, ips []net.IP, ttl time.Duration, isNegative bool) {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Use negative TTL for negative responses
	cacheTTL := ttl
	if isNegative {
		cacheTTL = c.config.NegativeTTL
		if cacheTTL == 0 {
			cacheTTL = 60 * time.Second // Default negative TTL
		}
	} else if cacheTTL == 0 {
		cacheTTL = c.config.DefaultTTL
	}

	now := time.Now()
	entry := &CacheEntry{
		IPs:        make([]net.IP, len(ips)),
		ExpiresAt:  now.Add(cacheTTL),
		StaleUntil: now.Add(cacheTTL * 2), // Stale period is 2x TTL
		IsNegative: isNegative,
	}
	copy(entry.IPs, ips)

	// Evict if at capacity
	if len(c.cache) >= c.config.MaxEntries {
		c.evictLRU()
	}

	// Move to front or add to front (O(1))
	if elem, exists := c.index[hostname]; exists {
		c.order.MoveToFront(elem)
	} else {
		elem := c.order.PushFront(hostname)
		c.index[hostname] = elem
	}

	c.cache[hostname] = entry

	slog.Debug("DNS cache entry stored",
		"hostname", hostname,
		"ips", len(ips),
		"ttl", cacheTTL,
		"is_negative", isNegative)
}

// moveToFront moves a hostname to the front of the LRU list (O(1))
func (c *Cache) moveToFront(hostname string) {
	if elem, exists := c.index[hostname]; exists {
		c.order.MoveToFront(elem)
	}
}

// evictLRU removes the least recently used entry (O(1))
func (c *Cache) evictLRU() {
	if c.order.Len() == 0 {
		return
	}

	// Remove oldest entry (last in order)
	elem := c.order.Back()
	if elem == nil {
		return
	}

	hostname := elem.Value.(string)
	c.order.Remove(elem)
	delete(c.index, hostname)
	delete(c.cache, hostname)

	slog.Debug("DNS cache entry evicted", "hostname", hostname)
}

// Clear removes all entries from the cache
func (c *Cache) Clear() {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = make(map[string]*CacheEntry)
	c.order = list.New()
	c.index = make(map[string]*list.Element)
}

// Size returns the current number of entries in the cache
func (c *Cache) Size() int {
	if c == nil {
		return 0
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.cache)
}

// Stats returns cache statistics
type Stats struct {
	Size      int
	MaxSize   int
	HitRate   float64
	Hits      uint64
	Misses    uint64
	Evictions uint64
}

var (
	cacheHits   uint64
	cacheMisses uint64
	cacheMu     sync.RWMutex
)

// RecordHit records a cache hit
func (c *Cache) RecordHit() {
	if c == nil {
		return
	}
	cacheMu.Lock()
	cacheHits++
	cacheMu.Unlock()
}

// RecordMiss records a cache miss
func (c *Cache) RecordMiss() {
	if c == nil {
		return
	}
	cacheMu.Lock()
	cacheMisses++
	cacheMu.Unlock()
}

// GetStats returns cache statistics
func (c *Cache) GetStats() Stats {
	if c == nil {
		return Stats{}
	}

	cacheMu.RLock()
	hits := cacheHits
	misses := cacheMisses
	cacheMu.RUnlock()

	c.mu.RLock()
	size := len(c.cache)
	c.mu.RUnlock()

	total := hits + misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}

	return Stats{
		Size:    size,
		MaxSize: c.config.MaxEntries,
		HitRate: hitRate,
		Hits:    hits,
		Misses:  misses,
	}
}

// Stop signals all background goroutines (refresh loop) to exit.
func (c *Cache) Stop() {
	if c == nil {
		return
	}
	close(c.stopCh)
}

// backgroundRefreshLoop refreshes entries before they expire
func (c *Cache) backgroundRefreshLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.refreshExpiringEntries()
		case <-c.stopCh:
			slog.Info("DNS cache background refresh loop stopped")
			return
		}
	}
}

// refreshExpiringEntries refreshes entries that are about to expire
func (c *Cache) refreshExpiringEntries() {
	c.mu.RLock()
	entriesToRefresh := make([]string, 0)
	now := time.Now()

	for hostname, entry := range c.cache {
		// Refresh if entry expires within 10% of TTL
		timeUntilExpiry := entry.ExpiresAt.Sub(now)
		ttl := entry.ExpiresAt.Sub(entry.ExpiresAt.Add(-c.config.DefaultTTL))
		if timeUntilExpiry > 0 && timeUntilExpiry < ttl/10 {
			entriesToRefresh = append(entriesToRefresh, hostname)
		}
	}
	c.mu.RUnlock()

	// Refresh entries in background
	for _, hostname := range entriesToRefresh {
		go func(h string) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Perform DNS lookup
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", h)
			if err == nil && len(ips) > 0 {
				// Update cache with new TTL
				c.mu.RLock()
				_, exists := c.cache[h]
				c.mu.RUnlock()

				if exists {
					ttl := c.config.DefaultTTL
					c.Put(h, ips, ttl, false)
					slog.Debug("DNS cache entry refreshed", "hostname", h)
				}
			}
		}(hostname)
	}
}
