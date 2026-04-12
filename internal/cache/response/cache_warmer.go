// Package handler contains the core HTTP request handler that orchestrates the proxy pipeline.
package responsecache

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/extension/cel"
	"github.com/soapbucket/sbproxy/internal/extension/lua"
	"github.com/soapbucket/sbproxy/internal/middleware/callback"
)

// CacheWarmer provides intelligent cache warming capabilities
type CacheWarmer struct {
	// Access tracking
	mu           sync.RWMutex
	accessLog    map[string]*AccessPattern
	hotThreshold int // Accesses needed to be considered "hot"

	// Caches to warm
	celCache      *cel.ExpressionCache
	luaCache      *lua.ScriptCache
	callbackCache *callback.CallbackCache
	responseCache cacher.Cacher

	// Configuration
	enabled        bool
	warmOnReload   bool
	predictiveWarm bool
	maxConcurrent  int

	// Metrics
	warmedCount     int64
	warmingFailures int64
	lastWarmingTime time.Time
}

// AccessPattern tracks access patterns for a cache key
type AccessPattern struct {
	Key         string
	AccessCount int64
	LastAccess  time.Time
	AvgInterval time.Duration
	Predictable bool
}

// CacheWarmerConfig configures cache warming behavior
type CacheWarmerConfig struct {
	Enabled        bool
	WarmOnReload   bool
	Predictive     bool
	HotThreshold   int           // Accesses to be considered hot (default: 10)
	MaxConcurrent  int           // Max concurrent warming operations (default: 5)
	WarmingTimeout time.Duration // Timeout for warming operations (default: 30s)
}

// DefaultCacheWarmerConfig returns default configuration
func DefaultCacheWarmerConfig() CacheWarmerConfig {
	return CacheWarmerConfig{
		Enabled:        true,
		WarmOnReload:   true,
		Predictive:     true,
		HotThreshold:   10,
		MaxConcurrent:  5,
		WarmingTimeout: 30 * time.Second,
	}
}

// NewCacheWarmer creates a new cache warmer
func NewCacheWarmer(config CacheWarmerConfig) *CacheWarmer {
	return &CacheWarmer{
		accessLog:      make(map[string]*AccessPattern),
		hotThreshold:   config.HotThreshold,
		enabled:        config.Enabled,
		warmOnReload:   config.WarmOnReload,
		predictiveWarm: config.Predictive,
		maxConcurrent:  config.MaxConcurrent,
	}
}

// SetCELCache sets the CEL expression cache
func (cw *CacheWarmer) SetCELCache(cache *cel.ExpressionCache) {
	cw.celCache = cache
}

// SetLuaCache sets the Lua script cache
func (cw *CacheWarmer) SetLuaCache(cache *lua.ScriptCache) {
	cw.luaCache = cache
}

// SetCallbackCache sets the callback cache
func (cw *CacheWarmer) SetCallbackCache(cache *callback.CallbackCache) {
	cw.callbackCache = cache
}

// SetResponseCache sets the response cache
func (cw *CacheWarmer) SetResponseCache(cache cacher.Cacher) {
	cw.responseCache = cache
}

// RecordAccess records an access pattern for a cache key
func (cw *CacheWarmer) RecordAccess(key string) {
	if !cw.enabled || !cw.predictiveWarm {
		return
	}

	cw.mu.Lock()
	defer cw.mu.Unlock()

	pattern, exists := cw.accessLog[key]
	if !exists {
		pattern = &AccessPattern{
			Key:         key,
			AccessCount: 0,
			LastAccess:  time.Now(),
		}
		cw.accessLog[key] = pattern
	}

	// Update access pattern
	now := time.Now()
	if pattern.AccessCount > 0 {
		interval := now.Sub(pattern.LastAccess)

		// Calculate average interval (exponential moving average)
		if pattern.AvgInterval == 0 {
			pattern.AvgInterval = interval
		} else {
			// EMA with alpha = 0.3
			pattern.AvgInterval = time.Duration(
				0.7*float64(pattern.AvgInterval) + 0.3*float64(interval),
			)
		}

		// Check if predictable (consistent interval)
		if pattern.AccessCount > 5 {
			deviation := float64(interval-pattern.AvgInterval) / float64(pattern.AvgInterval)
			pattern.Predictable = deviation < 0.2 && deviation > -0.2
		}
	}

	pattern.AccessCount++
	pattern.LastAccess = now
}

// GetHotPaths returns paths that are frequently accessed
func (cw *CacheWarmer) GetHotPaths() []string {
	cw.mu.RLock()
	defer cw.mu.RUnlock()

	var hotPaths []string
	for key, pattern := range cw.accessLog {
		if pattern.AccessCount >= int64(cw.hotThreshold) {
			hotPaths = append(hotPaths, key)
		}
	}

	return hotPaths
}

// WarmExpressions warms CEL and Lua expression caches
func (cw *CacheWarmer) WarmExpressions(ctx context.Context, expressions []string, luaScripts []string, version string) error {
	if !cw.enabled {
		return nil
	}

	slog.Info("warming expression caches",
		"cel_count", len(expressions),
		"lua_count", len(luaScripts),
		"version", version)

	start := time.Now()
	var errCount int64

	// Build work items for bounded worker pool
	type workItem struct {
		isCEL bool
		expr  string
	}

	var items []workItem
	if cw.celCache != nil {
		for _, expr := range expressions {
			if expr != "" {
				items = append(items, workItem{isCEL: true, expr: expr})
			}
		}
	}
	if cw.luaCache != nil {
		for _, script := range luaScripts {
			if script != "" {
				items = append(items, workItem{isCEL: false, expr: script})
			}
		}
	}

	// Feed work items through a channel consumed by a bounded worker pool
	workCh := make(chan workItem, cw.maxConcurrent)
	var wg sync.WaitGroup

	// Spawn a fixed number of workers (bounded)
	for i := 0; i < cw.maxConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range workCh {
				if item.isCEL {
					if _, found := cw.celCache.Get(item.expr, version); found {
						continue
					}
					program, compileErr := cel.CompileAndCache(item.expr, version, cw.celCache)
					if compileErr != nil {
						slog.Warn("failed to warm CEL expression",
							"expr", item.expr[:min(50, len(item.expr))],
							"error", compileErr)
						atomic.AddInt64(&errCount, 1)
						atomic.AddInt64(&cw.warmingFailures, 1)
						continue
					}
					_ = program
					slog.Debug("warmed CEL expression", "expr", item.expr[:min(50, len(item.expr))])
				} else {
					if _, found := cw.luaCache.Get(item.expr, version); found {
						continue
					}
					fn, compileErr := lua.CompileAndCache(item.expr, version, cw.luaCache)
					if compileErr != nil {
						slog.Warn("failed to warm Lua script",
							"script", item.expr[:min(50, len(item.expr))],
							"error", compileErr)
						atomic.AddInt64(&errCount, 1)
						atomic.AddInt64(&cw.warmingFailures, 1)
						continue
					}
					_ = fn
					slog.Debug("warmed Lua script", "script", item.expr[:min(50, len(item.expr))])
				}
				atomic.AddInt64(&cw.warmedCount, 1)
			}
		}()
	}

	// Send work items, respecting context cancellation
	for _, item := range items {
		select {
		case <-ctx.Done():
			slog.Warn("expression cache warming cancelled", "error", ctx.Err())
			break
		case workCh <- item:
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(workCh)
	wg.Wait()

	cw.lastWarmingTime = time.Now()
	totalErrors := atomic.LoadInt64(&errCount)

	slog.Info("expression cache warming complete",
		"duration", time.Since(start),
		"warmed", atomic.LoadInt64(&cw.warmedCount),
		"errors", totalErrors)

	if totalErrors > 0 {
		return fmt.Errorf("warming failed with %d errors", totalErrors)
	}

	return nil
}

// WarmCallbacks pre-fetches callback responses
func (cw *CacheWarmer) WarmCallbacks(ctx context.Context, callbacks []*callback.Callback) error {
	if !cw.enabled || cw.callbackCache == nil {
		return nil
	}

	slog.Info("warming callback cache", "count", len(callbacks))

	start := time.Now()

	// Filter to cacheable callbacks
	var cacheable []*callback.Callback
	for _, cb := range callbacks {
		if cb.CacheDuration.Duration != 0 {
			cacheable = append(cacheable, cb)
		}
	}

	// Feed work through a channel consumed by a bounded worker pool
	workCh := make(chan *callback.Callback, cw.maxConcurrent)
	var wg sync.WaitGroup

	for i := 0; i < cw.maxConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cb := range workCh {
				// Generate cache key for this callback
				cacheKey := cb.GenerateCacheKey(nil)

				// Check if already cached
				if _, found, _ := cw.callbackCache.Get(ctx, cacheKey); found {
					continue
				}

				// Execute the callback to warm the cache. The Fetch method handles
				// storing the result in the callback cache when a CacheDuration is set.
				resp, fetchErr := cb.Fetch(ctx, nil)
				if fetchErr != nil {
					slog.Warn("failed to warm callback", "url", cb.URL, "error", fetchErr)
					continue
				}
				_ = resp
				slog.Debug("warmed callback", "url", cb.URL)
				atomic.AddInt64(&cw.warmedCount, 1)
			}
		}()
	}

	// Send work items, respecting context cancellation
	for _, cb := range cacheable {
		select {
		case <-ctx.Done():
			slog.Warn("callback cache warming cancelled", "error", ctx.Err())
			break
		case workCh <- cb:
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(workCh)
	wg.Wait()

	slog.Info("callback cache warming complete",
		"duration", time.Since(start),
		"warmed", atomic.LoadInt64(&cw.warmedCount))

	return nil
}

// WarmResult reports the outcome of a cache warming operation.
type WarmResult struct {
	Warmed  int64 `json:"warmed"`
	Failed  int64 `json:"failed"`
	Skipped int64 `json:"skipped"`
}

// WarmResponseCache warms the response cache by making real HTTP GET requests
// to the provided URLs and storing the responses. Concurrency is capped at
// 10 concurrent warm requests. Each URL must be a full URL
// (e.g. "https://example.com/api/data") so the warmer can reach the upstream.
func (cw *CacheWarmer) WarmResponseCache(ctx context.Context, urls []string) (WarmResult, error) {
	if !cw.enabled || cw.responseCache == nil {
		return WarmResult{}, nil
	}

	slog.Info("warming response cache", "urls", len(urls))

	start := time.Now()

	// Cap concurrency at 10 for warm requests, regardless of maxConcurrent setting.
	concurrency := cw.maxConcurrent
	if concurrency <= 0 || concurrency > 10 {
		concurrency = 10
	}

	var (
		warmed  int64
		failed  int64
		skipped int64
	)

	client := &http.Client{Timeout: 15 * time.Second}

	// Feed work through a channel consumed by a bounded worker pool
	workCh := make(chan string, concurrency)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rawURL := range workCh {
				// Check if already cached
				cacheKey := fmt.Sprintf("GET:%s", rawURL)
				if _, err := cw.responseCache.Get(ctx, ResponseCacheType, cacheKey); err == nil {
					atomic.AddInt64(&skipped, 1)
					continue
				}

				// Make a real HTTP GET request to the upstream URL.
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
				if err != nil {
					slog.Warn("cache warm: invalid URL", "url", rawURL, "error", err)
					atomic.AddInt64(&failed, 1)
					atomic.AddInt64(&cw.warmingFailures, 1)
					continue
				}

				resp, err := client.Do(req)
				if err != nil {
					slog.Warn("cache warm: request failed", "url", rawURL, "error", err)
					atomic.AddInt64(&failed, 1)
					atomic.AddInt64(&cw.warmingFailures, 1)
					continue
				}

				// Only cache successful responses.
				if resp.StatusCode >= 200 && resp.StatusCode < 400 {
					// Store the response body in cache with a default TTL.
					if putErr := cw.responseCache.PutWithExpires(ctx, ResponseCacheType, cacheKey, resp.Body, 5*time.Minute); putErr != nil {
						slog.Warn("cache warm: failed to store response", "url", rawURL, "error", putErr)
						atomic.AddInt64(&failed, 1)
						atomic.AddInt64(&cw.warmingFailures, 1)
					} else {
						atomic.AddInt64(&warmed, 1)
						atomic.AddInt64(&cw.warmedCount, 1)
					}
				} else {
					slog.Debug("cache warm: non-cacheable status", "url", rawURL, "status", resp.StatusCode)
					atomic.AddInt64(&failed, 1)
				}
				resp.Body.Close()
			}
		}()
	}

	// Send work items, respecting context cancellation
	for _, u := range urls {
		select {
		case <-ctx.Done():
			slog.Warn("response cache warming cancelled", "error", ctx.Err())
			break
		case workCh <- u:
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(workCh)
	wg.Wait()

	result := WarmResult{
		Warmed:  atomic.LoadInt64(&warmed),
		Failed:  atomic.LoadInt64(&failed),
		Skipped: atomic.LoadInt64(&skipped),
	}

	slog.Info("response cache warming complete",
		"duration", time.Since(start),
		"warmed", result.Warmed,
		"failed", result.Failed,
		"skipped", result.Skipped)

	return result, nil
}

// PredictiveWarm performs predictive warming based on access patterns
func (cw *CacheWarmer) PredictiveWarm(ctx context.Context) error {
	if !cw.enabled || !cw.predictiveWarm {
		return nil
	}

	cw.mu.RLock()
	defer cw.mu.RUnlock()

	slog.Info("starting predictive cache warming")

	var predictablePaths []string
	now := time.Now()

	// Find predictable paths that might be accessed soon
	for _, pattern := range cw.accessLog {
		if !pattern.Predictable || pattern.AvgInterval == 0 {
			continue
		}

		// Calculate expected next access time
		expectedNext := pattern.LastAccess.Add(pattern.AvgInterval)

		// If expected access is within the next minute, warm it
		if expectedNext.Sub(now) < time.Minute && expectedNext.After(now) {
			predictablePaths = append(predictablePaths, pattern.Key)
		}
	}

	if len(predictablePaths) > 0 {
		slog.Info("predictive warming",
			"paths", len(predictablePaths))

		_, err := cw.WarmResponseCache(ctx, predictablePaths)
		return err
	}

	return nil
}

// GetStats returns cache warming statistics
func (cw *CacheWarmer) GetStats() CacheWarmerStats {
	cw.mu.RLock()
	defer cw.mu.RUnlock()

	hotCount := 0
	predictableCount := 0

	for _, pattern := range cw.accessLog {
		if pattern.AccessCount >= int64(cw.hotThreshold) {
			hotCount++
		}
		if pattern.Predictable {
			predictableCount++
		}
	}

	return CacheWarmerStats{
		Enabled:          cw.enabled,
		TotalPatterns:    len(cw.accessLog),
		HotPaths:         hotCount,
		PredictablePaths: predictableCount,
		WarmedCount:      atomic.LoadInt64(&cw.warmedCount),
		Failures:         atomic.LoadInt64(&cw.warmingFailures),
		LastWarmingTime:  cw.lastWarmingTime,
	}
}

// CacheWarmerStats contains warming statistics
type CacheWarmerStats struct {
	Enabled          bool
	TotalPatterns    int
	HotPaths         int
	PredictablePaths int
	WarmedCount      int64
	Failures         int64
	LastWarmingTime  time.Time
}
