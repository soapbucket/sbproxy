// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/platform/circuitbreaker"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// ── cache_enhancements.go ─────────────────────────────────────────────────────

// CacheKeyNormalization defines how to normalize cache keys for better hit rates.
type CacheKeyNormalization struct {
	QueryParams       QueryParamNormalization `json:"query_params,omitempty"`
	Headers           HeaderNormalization     `json:"headers,omitempty"`
	Cookies           CookieNormalization     `json:"cookies,omitempty"`
	CaseNormalization bool                    `json:"case_normalization,omitempty"` // Normalize URL case
}

// QueryParamNormalization defines query parameter normalization.
type QueryParamNormalization struct {
	Ignore    []string `json:"ignore,omitempty"`    // Parameters to ignore (e.g., utm_*, tracking params)
	Sort      bool     `json:"sort,omitempty"`      // Sort parameters alphabetically
	LowerCase bool     `json:"lowercase,omitempty"` // Convert names to lowercase
}

// HeaderNormalization defines header normalization.
type HeaderNormalization struct {
	Ignore    []string          `json:"ignore,omitempty"`    // Headers to ignore
	Include   []string          `json:"include,omitempty"`   // Only include these headers
	Normalize map[string]string `json:"normalize,omitempty"` // Header name -> normalized name
}

// CookieNormalization defines cookie normalization.
type CookieNormalization struct {
	Ignore  []string `json:"ignore,omitempty"`  // Cookies to ignore
	Include []string `json:"include,omitempty"` // Only include these cookies
}

// StaleWhileRevalidate defines stale-while-revalidate behavior.
type StaleWhileRevalidate struct {
	Enabled         bool            `json:"enabled"`
	Duration        reqctx.Duration `json:"duration"`         // How long to serve stale content while revalidating
	StaleIfError    reqctx.Duration `json:"stale_if_error"`   // Serve stale on backend error
	MaxAge          reqctx.Duration `json:"max_age"`          // Maximum age before stale cannot be served
	AsyncRevalidate bool            `json:"async_revalidate"` // Revalidate in background (default: true)
}

// CachedResponse represents a cached HTTP response with metadata.
type CachedResponse struct {
	StatusCode   int                 `json:"status_code"`
	Headers      map[string][]string `json:"headers"`
	Body         []byte              `json:"body"`
	CachedAt     time.Time           `json:"cached_at"`
	ExpiresAt    time.Time           `json:"expires_at"`
	StaleAt      time.Time           `json:"stale_at,omitempty"` // When response becomes stale for SWR
	ETag         string              `json:"etag,omitempty"`
	LastModified string              `json:"last_modified,omitempty"`
}

// IsStale checks if the cached response is stale.
func (cr *CachedResponse) IsStale() bool {
	if cr.StaleAt.IsZero() {
		return time.Now().After(cr.ExpiresAt)
	}
	return time.Now().After(cr.StaleAt)
}

// IsExpired checks if the cached response is expired (cannot be served even as stale).
func (cr *CachedResponse) IsExpired() bool {
	return time.Now().After(cr.ExpiresAt)
}

// CanServeStale checks if stale content can still be served.
func (cr *CachedResponse) CanServeStale(maxAge time.Duration) bool {
	if maxAge == 0 {
		return false
	}
	age := time.Since(cr.CachedAt)
	return age < maxAge
}

// revalidationQueue manages background revalidation tasks.
type revalidationQueue struct {
	tasks   map[string]*revalidationTask
	mu      sync.RWMutex
	workers int
	queue   chan *revalidationTask
	ctx     context.Context
	cancel  context.CancelFunc
}

type revalidationTask struct {
	key       string
	url       string
	headers   http.Header
	cache     *ActionResponseCache
	timestamp time.Time
}

func newRevalidationQueue(workers int) *revalidationQueue {
	if workers == 0 {
		workers = 2 // Default to 2 background workers
	}

	ctx, cancel := context.WithCancel(context.Background())

	rq := &revalidationQueue{
		tasks:   make(map[string]*revalidationTask),
		workers: workers,
		queue:   make(chan *revalidationTask, 100),
		ctx:     ctx,
		cancel:  cancel,
	}

	// Start worker goroutines
	for i := 0; i < workers; i++ {
		go rq.worker(i)
	}

	return rq
}

func (rq *revalidationQueue) worker(id int) {
	slog.Debug("revalidation worker started", "worker_id", id)

	for {
		select {
		case <-rq.ctx.Done():
			slog.Debug("revalidation worker stopped", "worker_id", id)
			return
		case task := <-rq.queue:
			rq.processTask(task)
		}
	}
}

func (rq *revalidationQueue) processTask(task *revalidationTask) {
	if task == nil {
		return
	}

	slog.Debug("revalidating cache entry",
		"key", task.key,
		"url", task.url,
		"age", time.Since(task.timestamp))

	// Create request for revalidation
	req, err := http.NewRequestWithContext(rq.ctx, http.MethodGet, task.url, nil)
	if err != nil {
		slog.Error("failed to create revalidation request", "error", err, "url", task.url)
		return
	}

	// Copy headers
	for key, values := range task.headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// Perform request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		slog.Error("revalidation request failed", "error", err, "url", task.url)
		return
	}
	defer resp.Body.Close()

	// On successful revalidation, write-back to cache
	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			slog.Error("failed to read revalidation response body", "error", err, "key", task.key)
			return
		}

		slog.Debug("cache entry revalidated and updated", "key", task.key, "status", resp.StatusCode, "body_size", len(body))

		// Mark task complete to allow re-queuing
		rq.complete(task.key)
	}

	slog.Info("revalidation completed",
		"key", task.key,
		"status", resp.StatusCode,
		"duration", time.Since(task.timestamp))
}

func (rq *revalidationQueue) enqueue(task *revalidationTask) {
	rq.mu.Lock()
	defer rq.mu.Unlock()

	// Check if already queued
	if _, exists := rq.tasks[task.key]; exists {
		return
	}

	rq.tasks[task.key] = task

	select {
	case rq.queue <- task:
		// Queued successfully
	default:
		// Queue full, drop task
		slog.Warn("revalidation queue full, dropping task", "key", task.key)
		delete(rq.tasks, task.key)
	}
}

func (rq *revalidationQueue) complete(key string) {
	rq.mu.Lock()
	defer rq.mu.Unlock()
	delete(rq.tasks, key)
}

func (rq *revalidationQueue) shutdown() {
	rq.cancel()
	close(rq.queue)
}

// Global revalidation queue.
var globalRevalidationQueue *revalidationQueue
var revalidationQueueOnce sync.Once

func getRevalidationQueue() *revalidationQueue {
	revalidationQueueOnce.Do(func() {
		globalRevalidationQueue = newRevalidationQueue(2)
	})
	return globalRevalidationQueue
}

// NormalizeCacheKey normalizes a cache key according to the configuration.
func NormalizeCacheKey(r *http.Request, norm *CacheKeyNormalization) string {
	if norm == nil {
		return r.URL.String()
	}

	// Clone URL to avoid modifying original
	normalizedURL := *r.URL

	// Normalize query parameters
	if norm.QueryParams.Sort || len(norm.QueryParams.Ignore) > 0 || norm.QueryParams.LowerCase {
		values := normalizedURL.Query()
		normalized := url.Values{}

		for key, vals := range values {
			// Check if parameter should be ignored
			if shouldIgnoreParam(key, norm.QueryParams.Ignore) {
				continue
			}

			// Normalize key case
			normalizedKey := key
			if norm.QueryParams.LowerCase {
				normalizedKey = strings.ToLower(key)
			}

			normalized[normalizedKey] = vals
		}

		// Sort parameters if requested
		if norm.QueryParams.Sort {
			keys := make([]string, 0, len(normalized))
			for k := range normalized {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			sortedValues := url.Values{}
			for _, k := range keys {
				sortedValues[k] = normalized[k]
			}
			normalized = sortedValues
		}

		normalizedURL.RawQuery = normalized.Encode()
	}

	// Normalize URL case
	if norm.CaseNormalization {
		normalizedURL.Path = strings.ToLower(normalizedURL.Path)
	}

	// Build parts for cache key
	parts := []string{
		r.Method,
		normalizedURL.String(),
	}

	// Add normalized headers
	if len(norm.Headers.Include) > 0 || len(norm.Headers.Ignore) > 0 {
		headerParts := make([]string, 0)

		for key, values := range r.Header {
			if shouldIncludeHeader(key, norm.Headers) {
				normalizedKey := key
				if mapped, exists := norm.Headers.Normalize[key]; exists {
					normalizedKey = mapped
				}
				headerParts = append(headerParts, fmt.Sprintf("%s=%s", normalizedKey, strings.Join(values, ",")))
			}
		}

		if len(headerParts) > 0 {
			sort.Strings(headerParts)
			parts = append(parts, strings.Join(headerParts, "&"))
		}
	}

	// Add normalized cookies
	if len(norm.Cookies.Include) > 0 || len(norm.Cookies.Ignore) > 0 {
		cookieParts := make([]string, 0)

		for _, cookie := range r.Cookies() {
			if shouldIncludeCookie(cookie.Name, norm.Cookies) {
				cookieParts = append(cookieParts, fmt.Sprintf("%s=%s", cookie.Name, cookie.Value))
			}
		}

		if len(cookieParts) > 0 {
			sort.Strings(cookieParts)
			parts = append(parts, strings.Join(cookieParts, "&"))
		}
	}

	return strings.Join(parts, "|")
}

func shouldIgnoreParam(param string, ignoreList []string) bool {
	for _, ignored := range ignoreList {
		// Support wildcard matching
		if strings.HasSuffix(ignored, "*") {
			prefix := strings.TrimSuffix(ignored, "*")
			if strings.HasPrefix(param, prefix) {
				return true
			}
		} else if param == ignored {
			return true
		}
	}
	return false
}

func shouldIncludeHeader(header string, norm HeaderNormalization) bool {
	header = strings.ToLower(header)

	// Check ignore list first
	for _, ignored := range norm.Ignore {
		if strings.ToLower(ignored) == header {
			return false
		}
	}

	// If include list exists, only include those
	if len(norm.Include) > 0 {
		for _, included := range norm.Include {
			if strings.ToLower(included) == header {
				return true
			}
		}
		return false
	}

	return true
}

func shouldIncludeCookie(cookie string, norm CookieNormalization) bool {
	// Check ignore list first
	for _, ignored := range norm.Ignore {
		if ignored == cookie {
			return false
		}
	}

	// If include list exists, only include those
	if len(norm.Include) > 0 {
		for _, included := range norm.Include {
			if included == cookie {
				return true
			}
		}
		return false
	}

	return true
}

// SerializeCachedResponse serializes a CachedResponse to JSON.
func SerializeCachedResponse(cr *CachedResponse) ([]byte, error) {
	return json.Marshal(cr)
}

// DeserializeCachedResponse deserializes a CachedResponse from JSON.
func DeserializeCachedResponse(data []byte) (*CachedResponse, error) {
	var cr CachedResponse
	err := json.Unmarshal(data, &cr)
	return &cr, err
}

// ── config_cache.go ───────────────────────────────────────────────────────────

// ConfigCache provides a multi-layer cache for origin configurations.
// Layer 1: LRU in-memory cache (fast, limited size).
// Layer 2: Redis distributed cache (slow, unlimited, shared across instances).
type ConfigCache struct {
	// In-memory LRU cache
	lru *LRUCache

	// Redis fallback configuration
	redisURL    string
	redisClient *redis.Client
	breaker     *circuitbreaker.CircuitBreaker

	// TTL for cached configs
	ttl time.Duration

	// Metrics
	hits   int64
	misses int64
	mu     sync.RWMutex
}

// CacheEntry represents a cached config with metadata.
type CacheEntry struct {
	Config    *Config
	ExpiresAt time.Time
	Hash      string // For validation
}

// LRUCache is a simple LRU cache implementation.
type LRUCache struct {
	maxSize int
	items   map[string]*CacheEntry
	order   []string // Track access order for LRU eviction
	mu      sync.RWMutex
}

// NewLRUCache creates a new LRU cache with the specified capacity.
func NewLRUCache(maxSize int) *LRUCache {
	return &LRUCache{
		maxSize: maxSize,
		items:   make(map[string]*CacheEntry),
		order:   make([]string, 0, maxSize),
	}
}

// Get retrieves an item from the LRU cache.
func (lru *LRUCache) Get(key string) (*CacheEntry, bool) {
	lru.mu.RLock()
	entry, exists := lru.items[key]
	lru.mu.RUnlock()

	if !exists || (entry != nil && time.Now().After(entry.ExpiresAt)) {
		return nil, false
	}

	// Move to end (most recently used)
	lru.mu.Lock()
	for i, k := range lru.order {
		if k == key {
			lru.order = append(lru.order[:i], lru.order[i+1:]...)
			break
		}
	}
	lru.order = append(lru.order, key)
	lru.mu.Unlock()

	return entry, true
}

// Set adds or updates an item in the LRU cache.
func (lru *LRUCache) Set(key string, entry *CacheEntry) {
	lru.mu.Lock()
	defer lru.mu.Unlock()

	// Remove if exists (to update position)
	if _, exists := lru.items[key]; exists {
		for i, k := range lru.order {
			if k == key {
				lru.order = append(lru.order[:i], lru.order[i+1:]...)
				break
			}
		}
	}

	// Add to end
	lru.items[key] = entry
	lru.order = append(lru.order, key)

	// Evict oldest if over capacity
	if len(lru.order) > lru.maxSize {
		oldest := lru.order[0]
		delete(lru.items, oldest)
		lru.order = lru.order[1:]
	}
}

// Clear removes all entries.
func (lru *LRUCache) Clear() {
	lru.mu.Lock()
	defer lru.mu.Unlock()
	lru.items = make(map[string]*CacheEntry)
	lru.order = make([]string, 0, lru.maxSize)
}

// NewConfigCache creates a new config cache.
func NewConfigCache(redisURL string, lruSize int, ttl time.Duration) *ConfigCache {
	if ttl == 0 {
		ttl = 5 * time.Minute // Default 5 minute TTL
	}
	if lruSize == 0 {
		lruSize = 100 // Default 100 item LRU
	}

	cache := &ConfigCache{
		lru:      NewLRUCache(lruSize),
		redisURL: redisURL,
		ttl:      ttl,
		breaker: circuitbreaker.New(circuitbreaker.Config{
			Name:             "redis-config-cache",
			FailureThreshold: 5,
			SuccessThreshold: 3,
			Timeout:          10 * time.Second,
		}),
	}

	// Initialize Redis client if URL is provided
	if redisURL != "" {
		opts, err := redis.ParseURL(redisURL)
		if err != nil {
			slog.Error("failed to parse redis URL", "url", redisURL, "error", err)
		} else {
			cache.redisClient = redis.NewClient(opts)
		}
	}

	return cache
}

// Get retrieves a cached config, checking LRU first, then Redis.
func (cc *ConfigCache) Get(ctx context.Context, key string) (*Config, error) {
	// Check LRU cache first
	if entry, found := cc.lru.Get(key); found {
		cc.recordHit()
		slog.Debug("config cache LRU hit", "key", key)
		return entry.Config, nil
	}

	cc.recordMiss()

	// Check Redis fallback if configured
	if cc.redisURL != "" {
		if cfg, err := cc.getFromRedis(ctx, key); err == nil {
			// Cache in LRU for next access
			_ = cc.Set(ctx, key, cfg)
			slog.Debug("config cache Redis hit", "key", key)
			return cfg, nil
		}
		// Redis miss or error is not fatal - continue
	}

	return nil, fmt.Errorf("config not in cache: %s", key)
}

// Set stores a config in the cache (both LRU and Redis).
func (cc *ConfigCache) Set(ctx context.Context, key string, cfg *Config) error {
	entry := &CacheEntry{
		Config:    cfg,
		ExpiresAt: time.Now().Add(cc.ttl),
		Hash:      computeHash(cfg),
	}

	// Store in LRU
	cc.lru.Set(key, entry)

	// Store in Redis if configured
	if cc.redisURL != "" {
		if err := cc.setInRedis(ctx, key, entry); err != nil {
			slog.Warn("failed to store config in Redis", "key", key, "error", err)
			// Not fatal - LRU cache is still available
		}
	}

	return nil
}

// Invalidate removes a config from all caches.
func (cc *ConfigCache) Invalidate(ctx context.Context, key string) error {
	// Remove from LRU
	cc.lru.mu.Lock()
	delete(cc.lru.items, key)
	for i, k := range cc.lru.order {
		if k == key {
			cc.lru.order = append(cc.lru.order[:i], cc.lru.order[i+1:]...)
			break
		}
	}
	cc.lru.mu.Unlock()

	// Remove from Redis if configured
	if cc.redisURL != "" {
		if err := cc.removeFromRedis(ctx, key); err != nil {
			slog.Warn("failed to remove config from Redis", "key", key, "error", err)
		}
	}

	return nil
}

// getFromRedis retrieves a config from Redis (circuit breaker protected).
func (cc *ConfigCache) getFromRedis(ctx context.Context, key string) (*Config, error) {
	if cc.redisClient == nil {
		return nil, fmt.Errorf("redis not configured")
	}

	var cfg *Config
	err := cc.breaker.Call(func() error {
		value, err := cc.redisClient.Get(ctx, key).Bytes()
		if err != nil {
			if err == redis.Nil {
				return fmt.Errorf("key not found in redis")
			}
			return err
		}

		if err := json.Unmarshal(value, &cfg); err != nil {
			return fmt.Errorf("failed to unmarshal config from redis: %w", err)
		}

		return nil
	})

	if err == circuitbreaker.ErrCircuitOpen {
		slog.Warn("Redis circuit breaker open for config cache", "key", key)
		return nil, err
	}

	return cfg, err
}

// setInRedis stores a config in Redis (circuit breaker protected).
func (cc *ConfigCache) setInRedis(ctx context.Context, key string, entry *CacheEntry) error {
	if cc.redisClient == nil {
		return fmt.Errorf("redis not configured")
	}

	return cc.breaker.Call(func() error {
		data, err := json.Marshal(entry.Config)
		if err != nil {
			return fmt.Errorf("failed to marshal config for redis: %w", err)
		}

		if err := cc.redisClient.Set(ctx, key, data, cc.ttl).Err(); err != nil {
			return fmt.Errorf("failed to set config in redis: %w", err)
		}

		return nil
	})
}

// removeFromRedis removes a config from Redis (circuit breaker protected).
func (cc *ConfigCache) removeFromRedis(ctx context.Context, key string) error {
	if cc.redisClient == nil {
		return fmt.Errorf("redis not configured")
	}

	return cc.breaker.Call(func() error {
		if err := cc.redisClient.Del(ctx, key).Err(); err != nil {
			return fmt.Errorf("failed to delete config from redis: %w", err)
		}
		return nil
	})
}

// Clear clears all caches.
func (cc *ConfigCache) Clear() error {
	cc.lru.Clear()
	return nil
}

// Stats returns cache statistics.
func (cc *ConfigCache) Stats() map[string]interface{} {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	total := cc.hits + cc.misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(cc.hits) / float64(total) * 100
	}

	cc.lru.mu.RLock()
	lruSize := len(cc.lru.items)
	cc.lru.mu.RUnlock()

	return map[string]interface{}{
		"hits":     cc.hits,
		"misses":   cc.misses,
		"total":    total,
		"hit_rate": hitRate,
		"lru_size": lruSize,
		"lru_max":  cc.lru.maxSize,
	}
}

func (cc *ConfigCache) recordHit() {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.hits++
}

func (cc *ConfigCache) recordMiss() {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.misses++
}

// computeHash computes a SHA256 hash of a config for validation.
func computeHash(cfg *Config) string {
	data, _ := json.Marshal(cfg)
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

// ── action_response_cache.go ──────────────────────────────────────────────────

// ActionResponseCache provides action-level response caching configuration.
type ActionResponseCache struct {
	Enabled      bool            `json:"enabled"`
	TTL          reqctx.Duration `json:"ttl"`
	CacheKey     string          `json:"cache_key"`    // "method+url+headers[...]"
	VaryBy       []string        `json:"vary_by"`      // Headers to vary by
	VaryHeaders  []string        `json:"vary_headers"` // Alias for vary_by
	Conditions   CacheConditions `json:"conditions"`
	Invalidation CacheInvalidation `json:"invalidation"`

	// Cache control overrides
	IgnoreNoCache bool `json:"ignore_no_cache,omitempty"` // Cache responses even if Cache-Control says no-store or no-cache
	CachePrivate  bool `json:"cache_private,omitempty"`   // Cache responses with Cache-Control: private
	StoreNon200   bool `json:"store_non_200,omitempty"`   // Cache non-200 responses (404, 301, etc.)

	// Enhanced caching features
	StaleWhileRevalidate *StaleWhileRevalidate  `json:"stale_while_revalidate,omitempty"`
	KeyNormalization     *CacheKeyNormalization `json:"key_normalization,omitempty"`

	// Internal
	cache cacher.Cacher
}

// CacheConditions defines when to cache.
type CacheConditions struct {
	StatusCodes []int    `json:"status_codes"`
	Methods     []string `json:"methods"`
	MinSize     int      `json:"min_size"`
	MaxSize     int      `json:"max_size"`
}

// CacheInvalidation defines cache invalidation rules.
type CacheInvalidation struct {
	OnMethods []string `json:"on_methods"` // Invalidate on these methods
	Pattern   string   `json:"pattern"`    // URL pattern to invalidate
}

// ShouldCache determines if a response should be cached.
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

// GenerateCacheKey creates a cache key based on the configured strategy.
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

// ShouldInvalidate checks if a request should trigger cache invalidation.
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

// InvalidatePattern invalidates cache entries matching a pattern.
func (arc *ActionResponseCache) InvalidatePattern(ctx context.Context, pattern string) error {
	if arc.cache == nil {
		return fmt.Errorf("cache not configured")
	}

	slog.Info("invalidating cache pattern", "pattern", pattern)

	return arc.cache.DeleteByPattern(ctx, "action", pattern)
}

// SetCache sets the cache backend.
func (arc *ActionResponseCache) SetCache(cache cacher.Cacher) {
	arc.cache = cache
}

// Get retrieves a cached response.
// Returns: data, isStale, found.
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

// Put stores a response in cache.
func (arc *ActionResponseCache) Put(ctx context.Context, key string, data []byte) error {
	if arc.cache == nil {
		return fmt.Errorf("cache not configured")
	}

	return arc.cache.PutWithExpires(ctx, "action", key, strings.NewReader(string(data)), arc.TTL.Duration)
}

// PutCachedResponse stores a CachedResponse in cache with SWR support.
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

// TriggerRevalidation triggers background revalidation of a cache entry.
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

// ActionResponseCacheStats tracks cache statistics.
type ActionResponseCacheStats struct {
	Hits          int64
	Misses        int64
	Puts          int64
	Invalidations int64
}

// HitRate returns the cache hit rate percentage.
func (s ActionResponseCacheStats) HitRate() float64 {
	total := s.Hits + s.Misses
	if total == 0 {
		return 0.0
	}
	return float64(s.Hits) / float64(total) * 100.0
}
