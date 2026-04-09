// Package handler contains the core HTTP request handler that orchestrates the proxy pipeline.
package responsecache

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pquerna/cachecontrol/cacheobject"
	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"golang.org/x/sync/singleflight"
)

const (
	// ResponseCacheType is the cache type for response caching
	ResponseCacheType = "response"

	// DefaultResponseTTL is the default TTL for cached responses
	DefaultResponseTTL = 5 * time.Minute

	// MaxCacheableSize is the maximum size of a response to cache (10MB)
	MaxCacheableSize = 10 * 1024 * 1024
)

// ResponseCacheConfig configures response caching behavior
type ResponseCacheConfig struct {
	Enabled       bool
	DefaultTTL    time.Duration
	MaxSize       int
	CachePrivate  bool
	IgnoreNoCache bool
	StoreNon200   bool
	VaryHeaders   []string
}

// DefaultResponseCacheConfig returns default configuration
func DefaultResponseCacheConfig() ResponseCacheConfig {
	return ResponseCacheConfig{
		Enabled:       true,
		DefaultTTL:    DefaultResponseTTL,
		MaxSize:       MaxCacheableSize,
		CachePrivate:  false,
		IgnoreNoCache: false,
		StoreNon200:   false,
		VaryHeaders:   []string{"Accept-Encoding"},
	}
}

// singleflightResult holds the captured response from a singleflight backend call.
type singleflightResult struct {
	status         int
	size           int
	headerSnapshot http.Header
	bodySnapshot   []byte
}

// ResponseCacheHandler creates a response caching middleware using L3 cache.
// It uses singleflight to prevent cache stampede: when a cached response expires,
// only one goroutine fetches from the backend while others wait for the result.
func ResponseCacheHandler(cache cacher.Cacher, config ResponseCacheConfig) func(http.Handler) http.Handler {
	var sfGroup singleflight.Group

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only cache GET and HEAD requests
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}

			// Generate cache key
			cacheKey := generateResponseCacheKey(r, config.VaryHeaders)
			ctx := r.Context()

			// Get config ID from request data for metrics
			configID := "unknown"
			if requestData := reqctx.GetRequestData(r.Context()); requestData != nil && requestData.Config != nil {
				configData := reqctx.ConfigParams(requestData.Config)
				if id := configData.GetConfigID(); id != "" {
					configID = id
				}
			}

			// Check cache
			if cached, found := getResponseFromCache(ctx, cache, cacheKey); found {
				// Check for no-cache flag - bypass cache if present
				requestData := reqctx.GetRequestData(r.Context())
				if requestData != nil && requestData.NoCache {
					slog.Debug("response cache: bypassing cache due to no-cache flag",
						"method", r.Method,
						"url", r.URL.String(),
						"cache_key", cacheKey)
					// Continue to next handler (don't serve from cache)
				} else {
					// Record cache hit
					metric.CacherHit(ResponseCacheType)
					recordCacheHit(configID, ResponseCacheType)

					// Store cache key in RequestData for request logging
					if requestData := reqctx.GetRequestData(r.Context()); requestData != nil {
						requestData.ResponseCacheKey = cacheKey
						requestData.ResponseCacheHit = true
						requestData.AddDebugHeader(httputil.HeaderXSbCacheKey, cacheKey)
					}

					slog.Debug("response cache hit",
						"method", r.Method,
						"url", r.URL.String(),
						"cache_key", cacheKey,
						"size", cached.Size,
						"config_id", configID)

					// Check conditional requests
					if handleConditionalRequest(w, r, cached) {
						return // 304 Not Modified sent
					}

					// Serve from cache
					slog.Debug("serving cached response",
						"method", r.Method,
						"url", r.URL.String(),
						"size", cached.Size,
						"cache_key", cacheKey)

					serveFromCache(w, r, cached, cacheKey)
					return
				}
			}

			// Record cache miss
			metric.CacherMiss(ResponseCacheType)
			recordCacheMiss(configID, ResponseCacheType)

			slog.Debug("response cache miss",
				"method", r.Method,
				"url", r.URL.String(),
				"cache_key", cacheKey,
				"config_id", configID)

			// Add cache miss header
			w.Header().Set("X-Cache", "MISS")

			// Cache miss - use singleflight to prevent cache stampede.
			// Only one goroutine fetches from the backend for a given cache key;
			// others wait for the result.
			sfVal, err, shared := sfGroup.Do(cacheKey, func() (any, error) {
				recorder := newResponseRecorder(w, config.MaxSize)
				next.ServeHTTP(recorder, r)

				// Snapshot headers synchronously before the ResponseWriter is recycled
				headerSnapshot := recorder.Header().Clone()
				bodySnapshot := make([]byte, recorder.body.Len())
				copy(bodySnapshot, recorder.body.Bytes())

				return &singleflightResult{
					status:         recorder.status,
					size:           recorder.size,
					headerSnapshot: headerSnapshot,
					bodySnapshot:   bodySnapshot,
				}, nil
			})

			if err != nil {
				// Singleflight error - fall through to a direct backend call
				slog.Error("singleflight error, falling back to direct backend call",
					"cache_key", cacheKey,
					"error", err)
				next.ServeHTTP(w, r)
				return
			}

			result := sfVal.(*singleflightResult)

			if shared {
				slog.Debug("response cache: singleflight shared result",
					"cache_key", cacheKey,
					"config_id", configID)
			}

			// Save to cache asynchronously using a detached context so that
			// request cancellation does not abort the cache write.
			saveCtx := context.WithoutCancel(ctx)
			go func() {
				defer func() {
					if p := recover(); p != nil {
						slog.Error("panic in async cache save",
							"cache_key", cacheKey,
							"panic", p)
					}
				}()
				saveResponseToCacheFromSnapshot(saveCtx, cache, cacheKey, result.status, result.size, result.headerSnapshot, result.bodySnapshot, config, configID)
			}()
		})
	}
}

// generateResponseCacheKey creates a cache key based on request and vary headers
func generateResponseCacheKey(r *http.Request, varyHeaders []string) string {
	// Use httputil.GenerateCacheKey which includes workspace_id and config_id from RequestData.Config
	return httputil.GenerateCacheKey(r)
}

// getResponseFromCache retrieves a cached response
func getResponseFromCache(ctx context.Context, cache cacher.Cacher, key string) (*CachedResponse, bool) {
	reader, err := cache.Get(ctx, ResponseCacheType, key)
	if err != nil {
		return nil, false
	}

	var cached CachedResponse
	if err := json.NewDecoder(reader).Decode(&cached); err != nil {
		slog.Error("failed to decode cached response", "error", err)
		return nil, false
	}

	// Expiry checking would be based on cache TTL, not stored in response
	// The cacher itself handles expiration

	return &cached, true
}

// handleConditionalRequest handles If-None-Match and If-Modified-Since
func handleConditionalRequest(w http.ResponseWriter, r *http.Request, cached *CachedResponse) bool {
	// ETag support
	if etag := cached.Headers.Get("ETag"); etag != "" {
		if noneMatch := r.Header.Get("If-None-Match"); noneMatch == etag {
			w.WriteHeader(http.StatusNotModified)
			return true
		}
	}

	// Last-Modified support
	if lastModified := cached.Headers.Get("Last-Modified"); lastModified != "" {
		if modifiedSince := r.Header.Get("If-Modified-Since"); modifiedSince != "" {
			if parsedModified, err := time.Parse(time.RFC1123, modifiedSince); err == nil {
				if parsedLast, err := time.Parse(time.RFC1123, lastModified); err == nil {
					if !parsedLast.After(parsedModified) {
						w.WriteHeader(http.StatusNotModified)
						return true
					}
				}
			}
		}
	}

	return false
}

// serveFromCache writes the cached response
func serveFromCache(w http.ResponseWriter, r *http.Request, cached *CachedResponse, cacheKey string) {
	// Copy headers
	for key, values := range cached.Headers {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Add cache hit header
	w.Header().Set("X-Cache", "HIT")

	// Add cache key header using RequestData
	if requestData := reqctx.GetRequestData(r.Context()); requestData != nil {
		requestData.AddDebugHeader(httputil.HeaderXSbCacheKey, cacheKey)
	}

	// Write status and body
	w.WriteHeader(cached.Status)
	w.Write(cached.Body)
}

// saveResponseToCache saves a response to cache
func saveResponseToCacheFromSnapshot(ctx context.Context, cache cacher.Cacher, key string, status int, size int, headers http.Header, body []byte, config ResponseCacheConfig, origin string) {
	// Don't cache if disabled
	if !config.Enabled {
		return
	}

	// Check status code
	if !config.StoreNon200 && status != http.StatusOK {
		slog.Debug("response not cached - non-200 status",
			"cache_key", key,
			"status", status,
			"origin", origin)
		return
	}

	// Check size
	if size > config.MaxSize {
		slog.Debug("response too large to cache",
			"cache_key", key,
			"size", size,
			"max", config.MaxSize,
			"origin", origin)
		metric.CacheEviction(origin, "response", "size_limit_exceeded")
		return
	}

	// Parse Cache-Control from snapshot headers
	cc, err := cacheobject.ParseResponseCacheControl(headers.Get("Cache-Control"))
	if err == nil {
		if cc.PrivatePresent && !config.CachePrivate {
			slog.Debug("response not cached - private",
				"cache_key", key,
				"origin", origin)
			return
		}

		if cc.NoStore && !config.IgnoreNoCache {
			slog.Debug("response not cached - no-store",
				"cache_key", key,
				"origin", origin)
			return
		}

		if cc.NoCachePresent && !config.IgnoreNoCache {
			slog.Debug("response not cached - no-cache",
				"cache_key", key,
				"origin", origin)
			return
		}
	}

	// Determine TTL
	ttl := config.DefaultTTL
	if cc != nil && cc.MaxAge > 0 {
		ttl = time.Duration(cc.MaxAge) * time.Second
	}

	cached := &CachedResponse{
		Status:  status,
		Headers: headers,
		Body:    body,
		Size:    size,
	}

	// Serialize
	data, err := json.Marshal(cached)
	if err != nil {
		slog.Error("failed to marshal response for caching",
			"cache_key", key,
			"origin", origin,
			"error", err)
		return
	}

	// Save to cache
	if err := cache.PutWithExpires(ctx, ResponseCacheType, key, bytes.NewReader(data), ttl); err != nil {
		slog.Error("failed to save response to cache",
			"cache_key", key,
			"origin", origin,
			"ttl", ttl,
			"size", cached.Size,
			"status", cached.Status,
			"error", err)
		metric.CacheEviction(origin, ResponseCacheType, "save_error")
	} else {
		slog.Debug("response cached",
			"cache_key", key,
			"origin", origin,
			"size", cached.Size,
			"ttl", ttl,
			"status", cached.Status)
	}
}

// responseRecorder captures response for caching
type responseRecorder struct {
	http.ResponseWriter
	status   int
	body     *bytes.Buffer
	size     int
	maxSize  int
	tooLarge bool
}

// responseRecorderPool reuses responseRecorder structs to avoid per-request heap allocation.
var responseRecorderPool = sync.Pool{
	New: func() any {
		return &responseRecorder{
			body: new(bytes.Buffer),
		}
	},
}

func newResponseRecorder(w http.ResponseWriter, maxSize int) *responseRecorder {
	rec := responseRecorderPool.Get().(*responseRecorder)
	rec.ResponseWriter = w
	rec.status = http.StatusOK
	rec.body.Reset()
	rec.size = 0
	rec.maxSize = maxSize
	rec.tooLarge = false
	return rec
}

func putResponseRecorder(rec *responseRecorder) {
	rec.ResponseWriter = nil
	responseRecorderPool.Put(rec)
}

// WriteHeader performs the write header operation on the responseRecorder.
func (r *responseRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// Write performs the write operation on the responseRecorder.
func (r *responseRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)

	// Capture body if not too large
	if !r.tooLarge && r.size+n <= r.maxSize {
		r.body.Write(b[:n])
		r.size += n
	} else {
		r.tooLarge = true
	}

	return n, err
}

// buildURLCacheKey builds a "GET:<url>" cache key using a pooled string builder.
func buildURLCacheKey(u *url.URL) string {
	s := u.String()
	b := cacher.GetBuilderWithSize(4 + len(s))
	b.WriteString("GET:")
	b.WriteString(s)
	key := b.String()
	cacher.PutBuilder(b)
	return key
}

// SaveCachedResponseURL saves a response to cache by URL
func SaveCachedResponseURL(cache cacher.Cacher, url *url.URL, cached *CachedResponse, ttl time.Duration) error {
	key := buildURLCacheKey(url)

	data, err := json.Marshal(cached)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return cache.PutWithExpires(ctx, ResponseCacheType, key, bytes.NewReader(data), ttl)
}

// GetCachedResponseURL retrieves a cached response by URL
func GetCachedResponseURL(cache cacher.Cacher, url *url.URL) (*CachedResponse, bool) {
	key := buildURLCacheKey(url)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	return getResponseFromCache(ctx, cache, key)
}

// updateCacheEfficiency calculates and updates cache efficiency metric
// Tracks hits and misses per origin/cacheLayer and calculates efficiency
var (
	cacheEfficiencyStats sync.Map
)

type cacheEfficiencyStat struct {
	hits         atomic.Int64
	misses       atomic.Int64
	lastReported atomic.Int64
}

// buildEfficiencyKey builds a cache efficiency stat key using a pooled string builder.
func buildEfficiencyKey(origin, cacheLayer string) string {
	b := cacher.GetBuilderWithSize(len(origin) + 1 + len(cacheLayer))
	b.WriteString(origin)
	b.WriteByte(':')
	b.WriteString(cacheLayer)
	key := b.String()
	cacher.PutBuilder(b)
	return key
}

// recordCacheHit records a cache hit for efficiency calculation
func recordCacheHit(origin, cacheLayer string) {
	key := buildEfficiencyKey(origin, cacheLayer)
	stat := getCacheEfficiencyStat(key)
	stat.hits.Add(1)
	updateEfficiencyIfNeeded(origin, cacheLayer, stat)
}

// recordCacheMiss records a cache miss for efficiency calculation
func recordCacheMiss(origin, cacheLayer string) {
	key := buildEfficiencyKey(origin, cacheLayer)
	stat := getCacheEfficiencyStat(key)
	stat.misses.Add(1)
	updateEfficiencyIfNeeded(origin, cacheLayer, stat)
}

// updateEfficiencyIfNeeded updates efficiency metric if threshold reached
func updateEfficiencyIfNeeded(origin, cacheLayer string, stat *cacheEfficiencyStat) {
	hits := stat.hits.Load()
	misses := stat.misses.Load()
	total := hits + misses
	if total > 0 && total%10 == 0 {
		lastReported := stat.lastReported.Load()
		if lastReported == total || !stat.lastReported.CompareAndSwap(lastReported, total) {
			return
		}
		efficiency := float64(hits) / float64(total)
		metric.CacheEfficiencySet(origin, cacheLayer, efficiency)
	}
}

func getCacheEfficiencyStat(key string) *cacheEfficiencyStat {
	if stat, ok := cacheEfficiencyStats.Load(key); ok {
		return stat.(*cacheEfficiencyStat)
	}
	actual, _ := cacheEfficiencyStats.LoadOrStore(key, &cacheEfficiencyStat{})
	return actual.(*cacheEfficiencyStat)
}
