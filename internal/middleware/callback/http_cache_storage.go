// Package callback executes HTTP callbacks to external services during request processing with retry and caching support.
package callback

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// HTTPCachedCallbackResponse represents a cached callback response with HTTP metadata
type HTTPCachedCallbackResponse struct {
	// Response data
	Data       map[string]any      `json:"data"`
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers"`

	// HTTP cache metadata
	ETag         string    `json:"etag,omitempty"`
	LastModified time.Time `json:"last_modified,omitempty"`
	VaryHeaders  []string  `json:"vary_headers,omitempty"`

	// Cache timing
	CachedAt   time.Time `json:"cached_at"`
	ExpiresAt  time.Time `json:"expires_at"`   // Fresh until
	StaleAt    time.Time `json:"stale_at"`     // Stale but usable until
	MaxStaleAt time.Time `json:"max_stale_at"` // Absolute expiry (stale-if-error)

	// Cache directives
	MaxAge               reqctx.Duration `json:"max_age"`
	StaleWhileRevalidate reqctx.Duration `json:"stale_while_revalidate,omitempty"`
	StaleIfError         reqctx.Duration `json:"stale_if_error,omitempty"`
	MustRevalidate       bool            `json:"must_revalidate"`
	NoCache              bool            `json:"no_cache"`
	NoStore              bool            `json:"no_store"`

	// Size and tier
	Size int64  `json:"size"`
	Tier string `json:"tier"` // "l2" or "l3"

	// Revalidation tracking
	Revalidating bool      `json:"revalidating"`
	RevalidateAt time.Time `json:"revalidate_at,omitempty"`
}

// GetState determines the current state of the cached response
func (c *HTTPCachedCallbackResponse) GetState(now time.Time) CacheState {
	if c.NoStore || (c.NoCache && c.MustRevalidate) {
		return StateExpired
	}

	if now.Before(c.ExpiresAt) {
		return StateFresh
	}

	if now.Before(c.StaleAt) {
		return StateStale
	}

	if now.Before(c.MaxStaleAt) {
		return StateStaleError
	}

	return StateExpired
}

// IsFresh checks if the response is still fresh
func (c *HTTPCachedCallbackResponse) IsFresh(now time.Time) bool {
	return c.GetState(now) == StateFresh
}

// CanServeStale checks if stale content can be served
func (c *HTTPCachedCallbackResponse) CanServeStale(now time.Time, allowStaleError bool) bool {
	state := c.GetState(now)
	return state == StateStale || (allowStaleError && state == StateStaleError)
}

// HTTPCallbackCache provides HTTP-aware caching functionality for callbacks
type HTTPCallbackCache struct {
	l2Cache cacher.Cacher
	l3Cache cacher.Cacher

	// HTTP cache parser
	parser *HTTPCacheParser

	// Revalidation tracking (in-memory map for thundering herd prevention)
	revalidatingMu sync.RWMutex
	revalidating   map[string]time.Time

	// Circuit breakers (reuse existing)
	circuitBreakers map[string]*CircuitBreaker
	cbMu            sync.RWMutex

	// Metrics
	metrics *CacheMetrics

	// Configuration
	l2MaxSize int64
}

// NewHTTPCallbackCache creates a new HTTP-aware callback cache
func NewHTTPCallbackCache(l2Cache, l3Cache cacher.Cacher, parser *HTTPCacheParser, l2MaxSize int64) *HTTPCallbackCache {
	// l2MaxSize is used as-is, no default needed

	return &HTTPCallbackCache{
		l2Cache:         l2Cache,
		l3Cache:         l3Cache,
		parser:          parser,
		revalidating:    make(map[string]time.Time),
		circuitBreakers: make(map[string]*CircuitBreaker),
		metrics:         &CacheMetrics{},
		l2MaxSize:       l2MaxSize,
	}
}

// selectTier selects the appropriate cache tier based on size
func (hcc *HTTPCallbackCache) selectTier(size int64) (cacher.Cacher, string) {
	if size < hcc.l2MaxSize {
		return hcc.l2Cache, "l2"
	}
	return hcc.l3Cache, "l3"
}

// Get retrieves a cached callback response
func (hcc *HTTPCallbackCache) Get(ctx context.Context, cacheKey string) (*HTTPCachedCallbackResponse, bool, error) {
	start := time.Now()

	// Try L2 first (faster for small objects)
	cache := hcc.l2Cache
	tier := "l2"

	reader, err := cache.Get(ctx, callbackCacheType, cacheKey)
	if err != nil && err != cacher.ErrNotFound {
		hcc.metrics.RecordError()
		slog.Error("failed to get from L2 cache",
			"cache_key", cacheKey,
			"error", err)
	}

	// If not found in L2, try L3
	if err == cacher.ErrNotFound || reader == nil {
		if hcc.l3Cache != nil {
			cache = hcc.l3Cache
			tier = "l3"
			reader, err = cache.Get(ctx, callbackCacheType, cacheKey)
		}
	}

	if err == cacher.ErrNotFound || reader == nil {
		hcc.metrics.RecordMiss()
		return nil, false, nil
	}

	if err != nil {
		hcc.metrics.RecordError()
		slog.Error("failed to get from cache",
			"tier", tier,
			"cache_key", cacheKey,
			"error", err)
		return nil, false, err
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		hcc.metrics.RecordError()
		slog.Error("failed to read cached data",
			"tier", tier,
			"cache_key", cacheKey,
			"error", err)
		return nil, false, err
	}

	var cached HTTPCachedCallbackResponse
	if err := json.Unmarshal(data, &cached); err != nil {
		hcc.metrics.RecordError()
		slog.Error("failed to unmarshal cached response",
			"tier", tier,
			"cache_key", cacheKey,
			"error", err)
		return nil, false, err
	}

	// Check if expired
	now := time.Now()
	state := cached.GetState(now)
	if state == StateExpired {
		// Return expired entry but mark as expired so caller can decide
		// This allows circuit breaker to serve expired content if needed
		hcc.metrics.RecordMiss()
		// Don't delete immediately - let caller decide if they want to serve expired
		// Delete expired entry asynchronously after a delay
		go func() {
			time.Sleep(1 * time.Second) // Give time for circuit breaker to use it
			deleteCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := cache.Delete(deleteCtx, callbackCacheType, cacheKey); err != nil {
				slog.Error("failed to delete expired cache entry",
					"tier", tier,
					"cache_key", cacheKey,
					"error", err)
			}
		}()
		// Still return the cached entry even if expired - caller can decide
		return &cached, true, nil
	}

	hcc.metrics.RecordHit(time.Since(start))
	slog.Debug("cache hit",
		"tier", tier,
		"state", state.String(),
		"cache_key", cacheKey,
		"age", now.Sub(cached.CachedAt))

	return &cached, true, nil
}

// Put stores a callback response in the appropriate cache tier
func (hcc *HTTPCallbackCache) Put(ctx context.Context, cacheKey string, data map[string]any, metadata *CacheMetadata, headers http.Header, statusCode int, size int64) error {
	// Select tier based on size
	cache, tier := hcc.selectTier(size)

	// Create cached response
	cached := HTTPCachedCallbackResponse{
		Data:                 data,
		StatusCode:           statusCode,
		Headers:              headers,
		ETag:                 metadata.ETag,
		LastModified:         metadata.LastModified,
		VaryHeaders:          metadata.VaryHeaders,
		CachedAt:             time.Now(),
		ExpiresAt:            metadata.ExpiresAt,
		StaleAt:              metadata.StaleAt,
		MaxStaleAt:           metadata.MaxStaleAt,
		MaxAge:               reqctx.Duration{Duration: metadata.MaxAge},
		StaleWhileRevalidate: reqctx.Duration{Duration: metadata.StaleWhileRevalidate},
		StaleIfError:         reqctx.Duration{Duration: metadata.StaleIfError},
		MustRevalidate:       metadata.MustRevalidate,
		NoCache:              metadata.NoCache,
		NoStore:              metadata.NoStore,
		Size:                 size,
		Tier:                 tier,
	}

	jsonData, err := json.Marshal(cached)
	if err != nil {
		hcc.metrics.RecordError()
		slog.Error("failed to marshal response for caching",
			"tier", tier,
			"cache_key", cacheKey,
			"error", err)
		return err
	}

	// Use MaxStaleAt as TTL for cache expiration
	ttl := time.Until(metadata.MaxStaleAt)
	if ttl <= 0 {
		return fmt.Errorf("invalid TTL: %v", ttl)
	}

	if err := cache.PutWithExpires(ctx, callbackCacheType, cacheKey, bytes.NewReader(jsonData), ttl); err != nil {
		hcc.metrics.RecordError()
		slog.Error("failed to put in cache",
			"tier", tier,
			"cache_key", cacheKey,
			"error", err)
		return err
	}

	slog.Debug("cached callback response",
		"tier", tier,
		"cache_key", cacheKey,
		"size", size,
		"ttl", ttl,
		"expires_at", metadata.ExpiresAt,
		"stale_at", metadata.StaleAt)

	return nil
}

// Invalidate removes a cached entry from both tiers
func (hcc *HTTPCallbackCache) Invalidate(ctx context.Context, cacheKey string) error {
	var errs []error

	if hcc.l2Cache != nil {
		if err := hcc.l2Cache.Delete(ctx, callbackCacheType, cacheKey); err != nil && err != cacher.ErrNotFound {
			errs = append(errs, err)
		}
	}

	if hcc.l3Cache != nil {
		if err := hcc.l3Cache.Delete(ctx, callbackCacheType, cacheKey); err != nil && err != cacher.ErrNotFound {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors invalidating cache: %v", errs)
	}

	hcc.metrics.RecordEviction()
	slog.Debug("invalidated cache entry",
		"cache_key", cacheKey)

	return nil
}

// IsRevalidating checks if a cache key is currently being revalidated
func (hcc *HTTPCallbackCache) IsRevalidating(cacheKey string) bool {
	hcc.revalidatingMu.RLock()
	defer hcc.revalidatingMu.RUnlock()

	revalidateTime, exists := hcc.revalidating[cacheKey]
	if !exists {
		return false
	}

	// Check if revalidation is stale (older than 5 minutes)
	if time.Since(revalidateTime) > 5*time.Minute {
		return false
	}

	return true
}

// SetRevalidating marks a cache key as being revalidated
func (hcc *HTTPCallbackCache) SetRevalidating(cacheKey string) {
	hcc.revalidatingMu.Lock()
	defer hcc.revalidatingMu.Unlock()
	hcc.revalidating[cacheKey] = time.Now()
}

// ClearRevalidating removes a cache key from revalidation tracking
func (hcc *HTTPCallbackCache) ClearRevalidating(cacheKey string) {
	hcc.revalidatingMu.Lock()
	defer hcc.revalidatingMu.Unlock()
	delete(hcc.revalidating, cacheKey)
}

// GetCircuitBreaker gets or creates a circuit breaker for a callback
func (hcc *HTTPCallbackCache) GetCircuitBreaker(cacheKey string) *CircuitBreaker {
	hcc.cbMu.RLock()
	cb, exists := hcc.circuitBreakers[cacheKey]
	hcc.cbMu.RUnlock()

	if exists {
		return cb
	}

	hcc.cbMu.Lock()
	defer hcc.cbMu.Unlock()

	// Double-check after acquiring write lock
	if cb, exists = hcc.circuitBreakers[cacheKey]; exists {
		return cb
	}

	cb = NewCircuitBreaker(defaultFailureThreshold, defaultSuccessThreshold, defaultTimeout)
	hcc.circuitBreakers[cacheKey] = cb

	return cb
}

// GetMetrics returns the cache metrics
func (hcc *HTTPCallbackCache) GetMetrics() map[string]interface{} {
	return hcc.metrics.GetStats()
}

// Cleanup removes expired revalidation tracking and circuit breakers
func (hcc *HTTPCallbackCache) Cleanup() {
	hcc.revalidatingMu.Lock()
	defer hcc.revalidatingMu.Unlock()

	now := time.Now()
	for key, revalidateTime := range hcc.revalidating {
		if now.Sub(revalidateTime) > 5*time.Minute {
			delete(hcc.revalidating, key)
		}
	}

	hcc.cbMu.Lock()
	defer hcc.cbMu.Unlock()

	for key, cb := range hcc.circuitBreakers {
		if cb.GetState() == circuitStateClosed && cb.failures == 0 && time.Since(cb.lastFailureTime) > 10*time.Minute {
			delete(hcc.circuitBreakers, key)
		}
	}
}
