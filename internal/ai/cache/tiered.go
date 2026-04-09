// Package cache implements semantic caching for AI responses using vector similarity search.
package cache

import (
	"context"
	"crypto/sha256"
	"fmt"
	"hash/fnv"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	json "github.com/goccy/go-json"
)

// TieredCacheConfig configures the multi-tier cache.
type TieredCacheConfig struct {
	Enabled           bool          `json:"enabled"`
	L1MaxEntries      int           `json:"l1_max_entries"`      // In-memory exact cache (default 10000)
	L1TTL             time.Duration `json:"l1_ttl"`              // Default 5m
	L2Enabled         bool          `json:"l2_enabled"`          // Redis tier
	L2TTL             time.Duration `json:"l2_ttl"`              // Default 30m
	SemanticEnabled   bool          `json:"semantic_enabled"`    // Semantic similarity
	SemanticThreshold float64       `json:"semantic_threshold"`  // Default 0.95
	CoalesceEnabled   bool          `json:"coalesce_enabled"`    // Request coalescing
	CoalesceWindow    time.Duration `json:"coalesce_window"`     // Default 100ms
	SWREnabled        bool          `json:"swr_enabled"`         // Stale-while-revalidate
	SWRTTL            time.Duration `json:"swr_ttl"`             // How long stale data can be served
}

func (c *TieredCacheConfig) applyDefaults() {
	if c.L1MaxEntries <= 0 {
		c.L1MaxEntries = 10000
	}
	if c.L1TTL <= 0 {
		c.L1TTL = 5 * time.Minute
	}
	if c.L2TTL <= 0 {
		c.L2TTL = 30 * time.Minute
	}
	if c.SemanticThreshold <= 0 {
		c.SemanticThreshold = 0.95
	}
	if c.CoalesceWindow <= 0 {
		c.CoalesceWindow = 100 * time.Millisecond
	}
	if c.SWRTTL <= 0 {
		c.SWRTTL = 10 * time.Minute
	}
}

// TieredCache provides multi-level caching for AI responses.
// Lookup order: L1 exact (in-memory) -> L2 exact (Redis) -> Semantic similarity -> Coalesce wait.
type TieredCache struct {
	config   TieredCacheConfig
	l1       *L1Cache
	l2       L2Store        // Optional Redis-backed cache tier.
	semantic *SemanticCache // Optional semantic similarity cache.
	coalesce *Coalescer     // Request deduplication.
	metrics  CacheMetrics
}

// CachedResponse holds a cached AI response with metadata.
type CachedResponse struct {
	Key       string          `json:"key"`
	Response  json.RawMessage `json:"response"`
	Model     string          `json:"model"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	SWRUntil  time.Time       `json:"swr_until,omitempty"` // Stale-while-revalidate deadline.
	HitCount  atomic.Int64    `json:"-"`
}

// IsExpired returns true if the cached response has exceeded its TTL.
func (cr *CachedResponse) IsExpired() bool {
	if cr.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(cr.ExpiresAt)
}

// IsStaleButServable returns true if expired but within the SWR window.
func (cr *CachedResponse) IsStaleButServable() bool {
	if cr.SWRUntil.IsZero() {
		return false
	}
	now := time.Now()
	return now.After(cr.ExpiresAt) && now.Before(cr.SWRUntil)
}

// L2Store is the interface for a Redis-backed cache tier.
type L2Store interface {
	Get(ctx context.Context, key string) (*CachedResponse, error)
	Set(ctx context.Context, key string, resp *CachedResponse, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
}

// CacheMetrics tracks cache performance using atomic counters.
type CacheMetrics struct {
	L1Hits       atomic.Int64
	L1Misses     atomic.Int64
	L2Hits       atomic.Int64
	L2Misses     atomic.Int64
	SemanticHits atomic.Int64
	CoalesceHits atomic.Int64
	SWRServed    atomic.Int64
	Stores       atomic.Int64
}

// Snapshot returns a point-in-time copy of the metrics.
func (m *CacheMetrics) Snapshot() CacheMetricsSnapshot {
	return CacheMetricsSnapshot{
		L1Hits:       m.L1Hits.Load(),
		L1Misses:     m.L1Misses.Load(),
		L2Hits:       m.L2Hits.Load(),
		L2Misses:     m.L2Misses.Load(),
		SemanticHits: m.SemanticHits.Load(),
		CoalesceHits: m.CoalesceHits.Load(),
		SWRServed:    m.SWRServed.Load(),
		Stores:       m.Stores.Load(),
	}
}

// CacheMetricsSnapshot is a non-atomic snapshot of CacheMetrics for reporting.
type CacheMetricsSnapshot struct {
	L1Hits       int64 `json:"l1_hits"`
	L1Misses     int64 `json:"l1_misses"`
	L2Hits       int64 `json:"l2_hits"`
	L2Misses     int64 `json:"l2_misses"`
	SemanticHits int64 `json:"semantic_hits"`
	CoalesceHits int64 `json:"coalesce_hits"`
	SWRServed    int64 `json:"swr_served"`
	Stores       int64 `json:"stores"`
}

// NewTieredCache creates a new multi-tier cache. l2 and semantic may be nil to
// disable those tiers.
func NewTieredCache(config TieredCacheConfig, l2 L2Store, semantic *SemanticCache) *TieredCache {
	config.applyDefaults()
	tc := &TieredCache{
		config: config,
		l1:     NewL1Cache(config.L1MaxEntries),
		l2:     l2,
		semantic: semantic,
	}
	if config.CoalesceEnabled {
		tc.coalesce = NewCoalescer(config.CoalesceWindow)
	}
	return tc
}

// Lookup checks all tiers in order: L1 exact -> L2 exact -> Semantic -> Coalesce wait.
// The embedding parameter is only used when semantic search is enabled and may be nil otherwise.
func (tc *TieredCache) Lookup(ctx context.Context, key string, embedding []float64) (*CachedResponse, error) {
	if !tc.config.Enabled {
		return nil, nil
	}

	// L1: in-memory exact match.
	if resp := tc.l1.Get(key); resp != nil {
		if !resp.IsExpired() {
			resp.HitCount.Add(1)
			tc.metrics.L1Hits.Add(1)
			slog.Debug("tiered cache L1 hit", "key", key)
			return resp, nil
		}
		// Check SWR.
		if tc.config.SWREnabled && resp.IsStaleButServable() {
			tc.metrics.SWRServed.Add(1)
			slog.Debug("tiered cache SWR served from L1", "key", key)
			return resp, nil
		}
		// Expired and not SWR-servable, remove it.
		tc.l1.Delete(key)
	}
	tc.metrics.L1Misses.Add(1)

	// L2: Redis exact match.
	if tc.config.L2Enabled && tc.l2 != nil {
		resp, err := tc.l2.Get(ctx, key)
		if err == nil && resp != nil {
			if !resp.IsExpired() {
				tc.metrics.L2Hits.Add(1)
				// Promote to L1.
				tc.l1.Set(key, resp)
				slog.Debug("tiered cache L2 hit, promoted to L1", "key", key)
				return resp, nil
			}
			if tc.config.SWREnabled && resp.IsStaleButServable() {
				tc.metrics.SWRServed.Add(1)
				tc.l1.Set(key, resp)
				slog.Debug("tiered cache SWR served from L2", "key", key)
				return resp, nil
			}
		}
		tc.metrics.L2Misses.Add(1)
	}

	// Semantic: similarity search.
	if tc.config.SemanticEnabled && tc.semantic != nil && len(embedding) > 0 {
		// Convert float64 embedding to float32 for vector store compatibility.
		f32 := make([]float32, len(embedding))
		for i, v := range embedding {
			f32[i] = float32(v)
		}
		results, err := tc.semantic.store.Search(ctx, f32, tc.config.SemanticThreshold, 1)
		if err == nil && len(results) > 0 {
			entry := results[0]
			if !entry.IsExpired() {
				tc.metrics.SemanticHits.Add(1)
				resp := &CachedResponse{
					Key:       entry.Key,
					Response:  entry.Response,
					Model:     entry.Model,
					CreatedAt: entry.CreatedAt,
					ExpiresAt: entry.CreatedAt.Add(entry.TTL),
				}
				// Promote to L1 under the exact key for future fast lookups.
				tc.l1.Set(key, resp)
				slog.Debug("tiered cache semantic hit", "key", key, "similarity", entry.Similarity)
				return resp, nil
			}
		}
	}

	return nil, nil
}

// Store writes to L1 and optionally L2, and resolves coalesced waiters.
func (tc *TieredCache) Store(ctx context.Context, key string, resp *CachedResponse, embedding []float64) error {
	if !tc.config.Enabled {
		return nil
	}

	tc.metrics.Stores.Add(1)

	// Set expiry if not already set.
	if resp.ExpiresAt.IsZero() {
		resp.ExpiresAt = time.Now().Add(tc.config.L1TTL)
	}
	if tc.config.SWREnabled && resp.SWRUntil.IsZero() {
		resp.SWRUntil = resp.ExpiresAt.Add(tc.config.SWRTTL)
	}

	// L1: always store.
	tc.l1.Set(key, resp)

	// L2: store if enabled.
	if tc.config.L2Enabled && tc.l2 != nil {
		if err := tc.l2.Set(ctx, key, resp, tc.config.L2TTL); err != nil {
			slog.Debug("tiered cache L2 store error", "key", key, "error", err)
			// Non-fatal: L1 still has the data.
		}
	}

	// Semantic: store embedding if enabled.
	if tc.config.SemanticEnabled && tc.semantic != nil && len(embedding) > 0 {
		f32 := make([]float32, len(embedding))
		for i, v := range embedding {
			f32[i] = float32(v)
		}
		entry := VectorEntry{
			Key:       key,
			Embedding: f32,
			Response:  resp.Response,
			Model:     resp.Model,
			CreatedAt: resp.CreatedAt,
			TTL:       tc.config.L1TTL,
		}
		if err := tc.semantic.store.Store(ctx, entry); err != nil {
			slog.Debug("tiered cache semantic store error", "key", key, "error", err)
		}
	}

	// Resolve coalesced waiters.
	if tc.coalesce != nil {
		tc.coalesce.Complete(key, resp, nil)
	}

	return nil
}

// Invalidate removes an entry from all tiers.
func (tc *TieredCache) Invalidate(ctx context.Context, key string) error {
	tc.l1.Delete(key)

	if tc.config.L2Enabled && tc.l2 != nil {
		if err := tc.l2.Delete(ctx, key); err != nil {
			slog.Debug("tiered cache L2 invalidate error", "key", key, "error", err)
		}
	}

	if tc.config.SemanticEnabled && tc.semantic != nil {
		if err := tc.semantic.store.Delete(ctx, key); err != nil {
			slog.Debug("tiered cache semantic invalidate error", "key", key, "error", err)
		}
	}

	return nil
}

// StartCoalesce registers an in-flight request. Returns true if this is the
// first requester (the one that should execute the request). Returns false if
// another request is already in-flight and the caller should wait via
// WaitCoalesce.
func (tc *TieredCache) StartCoalesce(key string) bool {
	if tc.coalesce == nil {
		return true
	}
	return tc.coalesce.Start(key)
}

// WaitCoalesce blocks until the in-flight request for key completes or the
// context is cancelled. Returns the cached response or an error.
func (tc *TieredCache) WaitCoalesce(ctx context.Context, key string) (*CachedResponse, error) {
	if tc.coalesce == nil {
		return nil, nil
	}
	resp, err := tc.coalesce.Wait(ctx, key)
	if err == nil && resp != nil {
		tc.metrics.CoalesceHits.Add(1)
	}
	return resp, err
}

// CompleteCoalesce resolves waiting coalesced requests with a result or error.
func (tc *TieredCache) CompleteCoalesce(key string, resp *CachedResponse, err error) {
	if tc.coalesce != nil {
		tc.coalesce.Complete(key, resp, err)
	}
}

// Metrics returns a point-in-time snapshot of cache metrics.
func (tc *TieredCache) Metrics() CacheMetricsSnapshot {
	return tc.metrics.Snapshot()
}

// ---------------------------------------------------------------------------
// L1Cache: sharded in-memory exact-match cache
// ---------------------------------------------------------------------------

const l1ShardCount = 16

// L1Cache is a sharded in-memory exact-match cache with LRU eviction.
type L1Cache struct {
	shards      [l1ShardCount]l1Shard
	maxPerShard int
}

type l1Shard struct {
	mu    sync.RWMutex
	items map[string]*CachedResponse
}

// NewL1Cache creates a new sharded in-memory cache. maxEntries is the total
// maximum across all shards.
func NewL1Cache(maxEntries int) *L1Cache {
	if maxEntries <= 0 {
		maxEntries = 10000
	}
	c := &L1Cache{
		maxPerShard: maxEntries / l1ShardCount,
	}
	if c.maxPerShard < 1 {
		c.maxPerShard = 1
	}
	for i := range c.shards {
		c.shards[i].items = make(map[string]*CachedResponse)
	}
	return c
}

func (c *L1Cache) shard(key string) *l1Shard {
	h := fnv.New32a()
	h.Write([]byte(key))
	return &c.shards[h.Sum32()%l1ShardCount]
}

// Get retrieves a cached response by key. Returns nil on miss.
func (c *L1Cache) Get(key string) *CachedResponse {
	s := c.shard(key)
	s.mu.RLock()
	resp := s.items[key]
	s.mu.RUnlock()
	return resp
}

// Set stores a cached response. Evicts the oldest entry if the shard is full.
func (c *L1Cache) Set(key string, resp *CachedResponse) {
	s := c.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	s.items[key] = resp

	// Evict if over capacity: remove the oldest entry by CreatedAt.
	if len(s.items) > c.maxPerShard {
		c.evictOldest(s)
	}
}

// Delete removes an entry by key.
func (c *L1Cache) Delete(key string) {
	s := c.shard(key)
	s.mu.Lock()
	delete(s.items, key)
	s.mu.Unlock()
}

// Size returns the total number of entries across all shards.
func (c *L1Cache) Size() int {
	total := 0
	for i := range c.shards {
		c.shards[i].mu.RLock()
		total += len(c.shards[i].items)
		c.shards[i].mu.RUnlock()
	}
	return total
}

// evictOldest removes the entry with the oldest CreatedAt in the shard.
// Caller must hold s.mu write lock.
func (c *L1Cache) evictOldest(s *l1Shard) {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, v := range s.items {
		if first || v.CreatedAt.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.CreatedAt
			first = false
		}
	}
	if oldestKey != "" {
		delete(s.items, oldestKey)
	}
}

// ---------------------------------------------------------------------------
// Coalescer: deduplicates in-flight identical requests
// ---------------------------------------------------------------------------

// Coalescer deduplicates in-flight identical requests so that only one backend
// call is made for concurrent identical cache keys.
type Coalescer struct {
	mu       sync.Mutex
	inflight map[string]*coalescedRequest
	window   time.Duration
}

type coalescedRequest struct {
	resp *CachedResponse
	err  error
	done chan struct{}
}

// NewCoalescer creates a new request coalescer with the given window duration.
func NewCoalescer(window time.Duration) *Coalescer {
	if window <= 0 {
		window = 100 * time.Millisecond
	}
	return &Coalescer{
		inflight: make(map[string]*coalescedRequest),
		window:   window,
	}
}

// Start registers an in-flight request for key. Returns true if this is the
// first requester (the caller should execute the actual request). Returns false
// if another request is already in-flight.
func (c *Coalescer) Start(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.inflight[key]; exists {
		return false
	}

	c.inflight[key] = &coalescedRequest{
		done: make(chan struct{}),
	}
	return true
}

// Wait blocks until the in-flight request for key completes or the context is
// cancelled. Returns the result from the first requester.
func (c *Coalescer) Wait(ctx context.Context, key string) (*CachedResponse, error) {
	c.mu.Lock()
	req, exists := c.inflight[key]
	c.mu.Unlock()

	if !exists {
		return nil, nil
	}

	select {
	case <-req.done:
		return req.resp, req.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Complete resolves all waiting coalesced requests for key with the given
// response and error.
func (c *Coalescer) Complete(key string, resp *CachedResponse, err error) {
	c.mu.Lock()
	req, exists := c.inflight[key]
	if exists {
		req.resp = resp
		req.err = err
		close(req.done)
		delete(c.inflight, key)
	}
	c.mu.Unlock()
}

// ---------------------------------------------------------------------------
// BuildCacheKey: deterministic cache key from request fields
// ---------------------------------------------------------------------------

// BuildCacheKey creates a deterministic cache key from request fields. The key
// is a hex-encoded SHA-256 hash of the model, messages, temperature, and
// maxTokens. This ensures identical requests always produce the same key.
func BuildCacheKey(model string, messages json.RawMessage, temperature *float64, maxTokens int) string {
	h := sha256.New()
	h.Write([]byte(model))
	h.Write([]byte{0})

	// Normalize messages JSON to ensure consistent key generation regardless of
	// key ordering or whitespace.
	normalized := normalizeJSON(messages)
	h.Write(normalized)
	h.Write([]byte{0})

	if temperature != nil {
		h.Write([]byte(fmt.Sprintf("%.6f", *temperature)))
	} else {
		h.Write([]byte("nil"))
	}
	h.Write([]byte{0})

	h.Write([]byte(fmt.Sprintf("%d", maxTokens)))

	return fmt.Sprintf("tiered:%x", h.Sum(nil))
}

// normalizeJSON re-marshals JSON to produce a deterministic byte representation
// with sorted keys.
func normalizeJSON(data json.RawMessage) []byte {
	if len(data) == 0 {
		return nil
	}
	var parsed interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return data // Fall back to raw bytes on parse error.
	}
	normalized, err := marshalSorted(parsed)
	if err != nil {
		return data
	}
	return normalized
}

// marshalSorted produces deterministic JSON with sorted object keys.
func marshalSorted(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		out := []byte("{")
		for i, k := range keys {
			if i > 0 {
				out = append(out, ',')
			}
			kb, _ := json.Marshal(k)
			out = append(out, kb...)
			out = append(out, ':')
			vb, err := marshalSorted(val[k])
			if err != nil {
				return nil, err
			}
			out = append(out, vb...)
		}
		out = append(out, '}')
		return out, nil
	case []interface{}:
		out := []byte("[")
		for i, item := range val {
			if i > 0 {
				out = append(out, ',')
			}
			ib, err := marshalSorted(item)
			if err != nil {
				return nil, err
			}
			out = append(out, ib...)
		}
		out = append(out, ']')
		return out, nil
	default:
		return json.Marshal(v)
	}
}
