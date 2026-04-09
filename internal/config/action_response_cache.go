// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/cache/store"
)

// ActionResponseCache provides action-level response caching configuration
type ActionResponseCache struct {
	Enabled    bool            `json:"enabled"`
	TTL        reqctx.Duration `json:"ttl"`
	CacheKey   string          `json:"cache_key"`       // "method+url+headers[...]"
	VaryBy     []string        `json:"vary_by"`         // Headers to vary by
	VaryHeaders []string       `json:"vary_headers"`    // Alias for vary_by
	Conditions CacheConditions `json:"conditions"`
	Invalidation CacheInvalidation `json:"invalidation"`

	// Cache control overrides
	IgnoreNoCache bool `json:"ignore_no_cache,omitempty"` // Cache responses even if Cache-Control says no-store or no-cache
	CachePrivate  bool `json:"cache_private,omitempty"`   // Cache responses with Cache-Control: private
	StoreNon200   bool `json:"store_non_200,omitempty"`   // Cache non-200 responses (404, 301, etc.)

	// Enhanced caching features
	StaleWhileRevalidate  *StaleWhileRevalidate  `json:"stale_while_revalidate,omitempty"`
	KeyNormalization      *CacheKeyNormalization `json:"key_normalization,omitempty"`
	
	// Internal
	cache cacher.Cacher
}

// CacheConditions defines when to cache
type CacheConditions struct {
	StatusCodes []int    `json:"status_codes"`
	Methods     []string `json:"methods"`
	MinSize     int      `json:"min_size"`
	MaxSize     int      `json:"max_size"`
}

// CacheInvalidation defines cache invalidation rules
type CacheInvalidation struct {
	OnMethods []string `json:"on_methods"` // Invalidate on these methods
	Pattern   string   `json:"pattern"`     // URL pattern to invalidate
}

// ShouldCache determines if a response should be cached
func (arc *ActionResponseCache) ShouldCache(r *http.Request, status int, size int) bool {
	if !arc.Enabled {
		return false
	}
	
	// Check method
	if len(arc.Conditions.Methods) > 0 {
		methodAllowed := false
		for _, m := range arc.Conditions.Methods {
			if r.Method == m {
				methodAllowed = true
				break
			}
		}
		if !methodAllowed {
			return false
		}
	}
	
	// Check status code
	if len(arc.Conditions.StatusCodes) > 0 {
		statusAllowed := false
		for _, sc := range arc.Conditions.StatusCodes {
			if status == sc {
				statusAllowed = true
				break
			}
		}
		if !statusAllowed {
			return false
		}
	}
	
	// Check size
	if arc.Conditions.MinSize > 0 && size < arc.Conditions.MinSize {
		return false
	}
	if arc.Conditions.MaxSize > 0 && size > arc.Conditions.MaxSize {
		return false
	}
	
	return true
}

// GenerateCacheKey creates a cache key based on the configured strategy
func (arc *ActionResponseCache) GenerateCacheKey(actionName string, r *http.Request) string {
	parts := []string{actionName}
	
	// Add workspace_id and config_id from RequestData.Config
	if requestData := reqctx.GetRequestData(r.Context()); requestData != nil && requestData.Config != nil {
		configParams := reqctx.ConfigParams(requestData.Config)
		if workspaceID := configParams.GetWorkspaceID(); workspaceID != "" {
			parts = append(parts, "workspace:"+workspaceID)
		}
		if configID := configParams.GetConfigID(); configID != "" {
			parts = append(parts, "config:"+configID)
		}
	}
	
	// Use key normalization if configured
	if arc.KeyNormalization != nil {
		normalizedKey := NormalizeCacheKey(r, arc.KeyNormalization)
		parts = append(parts, normalizedKey)
		return strings.Join(parts, ":")
	}
	
	// Parse cache key template (legacy behavior)
	if arc.CacheKey != "" {
		if strings.Contains(arc.CacheKey, "method") {
			parts = append(parts, r.Method)
		}
		if strings.Contains(arc.CacheKey, "url") {
			parts = append(parts, r.URL.String())
		}
		if strings.Contains(arc.CacheKey, "headers") {
			// Extract header names from "headers[Header1,Header2]"
			// Simplified version - just use VaryBy headers
			for _, header := range arc.VaryBy {
				parts = append(parts, r.Header.Get(header))
			}
		}
	} else {
		// Default: method + url
		parts = append(parts, r.Method, r.URL.String())
	}
	
	// Add vary hash
	if len(arc.VaryBy) > 0 {
		varyValues := make([]string, 0, len(arc.VaryBy))
		for _, header := range arc.VaryBy {
			varyValues = append(varyValues, r.Header.Get(header))
		}
		varyHash := md5.Sum([]byte(strings.Join(varyValues, "|")))
		parts = append(parts, fmt.Sprintf("%x", varyHash[:4]))
	}
	
	return strings.Join(parts, ":")
}

// ShouldInvalidate checks if a request should trigger cache invalidation
func (arc *ActionResponseCache) ShouldInvalidate(r *http.Request) bool {
	if len(arc.Invalidation.OnMethods) == 0 {
		return false
	}
	
	for _, method := range arc.Invalidation.OnMethods {
		if r.Method == method {
			return true
		}
	}
	
	return false
}

// InvalidatePattern invalidates cache entries matching a pattern
func (arc *ActionResponseCache) InvalidatePattern(ctx context.Context, pattern string) error {
	if arc.cache == nil {
		return fmt.Errorf("cache not configured")
	}
	
	slog.Info("invalidating cache pattern", "pattern", pattern)
	
	return arc.cache.DeleteByPattern(ctx, "action", pattern)
}

// SetCache sets the cache backend
func (arc *ActionResponseCache) SetCache(cache cacher.Cacher) {
	arc.cache = cache
}

// Get retrieves a cached response
// Returns: data, isStale, found
func (arc *ActionResponseCache) Get(ctx context.Context, key string) ([]byte, bool, bool) {
	if arc.cache == nil {
		return nil, false, false
	}
	
	reader, err := arc.cache.Get(ctx, "action", key)
	if err != nil {
		return nil, false, false
	}
	
	// Read all data
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, false, false
	}
	
	// Check if stale-while-revalidate is enabled
	if arc.StaleWhileRevalidate != nil && arc.StaleWhileRevalidate.Enabled {
		cachedResp, err := DeserializeCachedResponse(data)
		if err == nil {
			isStale := cachedResp.IsStale()
			
			// Check if we can still serve stale content
			if isStale && !cachedResp.CanServeStale(arc.StaleWhileRevalidate.MaxAge.Duration) {
				return nil, false, false
			}
			
			return data, isStale, true
		}
	}
	
	return data, false, true
}

// Put stores a response in cache
func (arc *ActionResponseCache) Put(ctx context.Context, key string, data []byte) error {
	if arc.cache == nil {
		return fmt.Errorf("cache not configured")
	}
	
	return arc.cache.PutWithExpires(ctx, "action", key, strings.NewReader(string(data)), arc.TTL.Duration)
}

// PutCachedResponse stores a CachedResponse in cache with SWR support
func (arc *ActionResponseCache) PutCachedResponse(ctx context.Context, key string, resp *CachedResponse) error {
	if arc.cache == nil {
		return fmt.Errorf("cache not configured")
	}
	
	// Set stale time if SWR is enabled
	if arc.StaleWhileRevalidate != nil && arc.StaleWhileRevalidate.Enabled {
		resp.StaleAt = resp.CachedAt.Add(arc.TTL.Duration - arc.StaleWhileRevalidate.Duration.Duration)
		resp.ExpiresAt = resp.CachedAt.Add(arc.StaleWhileRevalidate.MaxAge.Duration)
	} else {
		resp.ExpiresAt = resp.CachedAt.Add(arc.TTL.Duration)
	}
	
	data, err := SerializeCachedResponse(resp)
	if err != nil {
		return fmt.Errorf("failed to serialize cached response: %w", err)
	}
	
	return arc.cache.PutWithExpires(ctx, "action", key, strings.NewReader(string(data)), arc.TTL.Duration)
}

// TriggerRevalidation triggers background revalidation of a cache entry
func (arc *ActionResponseCache) TriggerRevalidation(key string, url string, headers http.Header) {
	if arc.StaleWhileRevalidate == nil || !arc.StaleWhileRevalidate.AsyncRevalidate {
		return
	}
	
	task := &revalidationTask{
		key:       key,
		url:       url,
		headers:   headers,
		cache:     arc,
		timestamp: time.Now(),
	}
	
	queue := getRevalidationQueue()
	queue.enqueue(task)
}

// ActionResponseCacheStats tracks cache statistics
type ActionResponseCacheStats struct {
	Hits       int64
	Misses     int64
	Puts       int64
	Invalidations int64
}

// HitRate returns the cache hit rate percentage
func (s ActionResponseCacheStats) HitRate() float64 {
	total := s.Hits + s.Misses
	if total == 0 {
		return 0.0
	}
	return float64(s.Hits) / float64(total) * 100.0
}

