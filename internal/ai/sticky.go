// sticky.go implements hash-based session affinity for AI provider routing.
package ai

import (
	"context"
	"hash/fnv"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"
)

const (
	defaultStickyTTL      = 30 * time.Minute
	stickyShardCount      = 16
	stickyCleanupInterval = 30 * time.Second
)

// StickySessionConfig configures hash-based session affinity for provider routing.
type StickySessionConfig struct {
	Enabled     bool          `json:"enabled,omitempty"`
	TTL         time.Duration `json:"ttl,omitempty"`
	HashHeaders []string      `json:"hash_headers,omitempty"` // Headers to hash for session key (default: ["Authorization", "X-API-Key"])
	HashCookies []string      `json:"hash_cookies,omitempty"` // Cookies to hash for session key
}

// stickyEntry holds a provider mapping with expiration.
type stickyEntry struct {
	provider  string
	expiresAt time.Time
}

// stickyShard is one shard of the sticky session map.
type stickyShard struct {
	mu      sync.RWMutex
	entries map[string]stickyEntry
}

// StickySessionManager provides hash-based session affinity using sharded in-memory storage.
type StickySessionManager struct {
	shards  [stickyShardCount]stickyShard
	ttl     time.Duration
	headers []string
	cookies []string
	cancel  context.CancelFunc
}

// NewStickySessionManager creates a new sticky session manager with the given configuration.
// A background goroutine evicts expired entries every 30 seconds.
func NewStickySessionManager(cfg *StickySessionConfig) *StickySessionManager {
	if cfg == nil {
		cfg = &StickySessionConfig{}
	}

	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = defaultStickyTTL
	}

	headers := cfg.HashHeaders
	if len(headers) == 0 {
		headers = []string{"Authorization", "X-API-Key"}
	}

	m := &StickySessionManager{
		ttl:     ttl,
		headers: headers,
		cookies: cfg.HashCookies,
	}

	for i := range m.shards {
		m.shards[i].entries = make(map[string]stickyEntry)
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	go m.cleanupLoop(ctx)

	return m
}

// Stop stops the background cleanup goroutine.
func (m *StickySessionManager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
}

// ComputeSessionKey hashes the configured headers and cookies from the request using FNV-1a.
// Returns an empty string if no relevant values are present.
func (m *StickySessionManager) ComputeSessionKey(r *http.Request) string {
	h := fnv.New64a()
	hasData := false

	for _, name := range m.headers {
		val := r.Header.Get(name)
		if val != "" {
			h.Write([]byte(name))
			h.Write([]byte("="))
			h.Write([]byte(val))
			h.Write([]byte(";"))
			hasData = true
		}
	}

	if len(m.cookies) > 0 {
		// Build a sorted cookie map for deterministic hashing
		cookieMap := make(map[string]string, len(m.cookies))
		for _, c := range r.Cookies() {
			cookieMap[c.Name] = c.Value
		}
		sorted := make([]string, 0, len(m.cookies))
		for _, name := range m.cookies {
			if _, ok := cookieMap[name]; ok {
				sorted = append(sorted, name)
			}
		}
		sort.Strings(sorted)
		for _, name := range sorted {
			h.Write([]byte("cookie:"))
			h.Write([]byte(name))
			h.Write([]byte("="))
			h.Write([]byte(cookieMap[name]))
			h.Write([]byte(";"))
			hasData = true
		}
	}

	if !hasData {
		return ""
	}

	return strconv.FormatUint(h.Sum64(), 36)
}

// getShard returns the shard for the given key.
func (m *StickySessionManager) getShard(key string) *stickyShard {
	h := fnv.New32a()
	h.Write([]byte(key))
	return &m.shards[h.Sum32()%stickyShardCount]
}

// GetStickyProvider looks up the provider affinity for a session key.
// Returns the provider name and true if a valid (non-expired) mapping exists.
func (m *StickySessionManager) GetStickyProvider(key string) (string, bool) {
	if key == "" {
		return "", false
	}

	shard := m.getShard(key)
	shard.mu.RLock()
	entry, ok := shard.entries[key]
	shard.mu.RUnlock()

	if !ok {
		return "", false
	}

	if time.Now().After(entry.expiresAt) {
		// Expired - clean up lazily
		shard.mu.Lock()
		if e, exists := shard.entries[key]; exists && time.Now().After(e.expiresAt) {
			delete(shard.entries, key)
		}
		shard.mu.Unlock()
		return "", false
	}

	return entry.provider, true
}

// SetStickyProvider records provider affinity for a session key.
func (m *StickySessionManager) SetStickyProvider(key string, providerName string) {
	if key == "" || providerName == "" {
		return
	}

	shard := m.getShard(key)
	shard.mu.Lock()
	shard.entries[key] = stickyEntry{
		provider:  providerName,
		expiresAt: time.Now().Add(m.ttl),
	}
	shard.mu.Unlock()
}

// cleanupLoop periodically evicts expired entries from all shards.
func (m *StickySessionManager) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(stickyCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.evictExpired()
		}
	}
}

// evictExpired removes all expired entries from every shard.
func (m *StickySessionManager) evictExpired() {
	now := time.Now()
	for i := range m.shards {
		shard := &m.shards[i]
		shard.mu.Lock()
		for k, entry := range shard.entries {
			if now.After(entry.expiresAt) {
				delete(shard.entries, k)
			}
		}
		shard.mu.Unlock()
	}
}

// Len returns the total number of active (non-expired) sticky entries across all shards.
func (m *StickySessionManager) Len() int {
	total := 0
	now := time.Now()
	for i := range m.shards {
		shard := &m.shards[i]
		shard.mu.RLock()
		for _, entry := range shard.entries {
			if now.Before(entry.expiresAt) {
				total++
			}
		}
		shard.mu.RUnlock()
	}
	return total
}
