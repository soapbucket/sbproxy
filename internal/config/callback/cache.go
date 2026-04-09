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
	"sync/atomic"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

const (
	callbackCacheType = "callbacks"

	// Circuit breaker states
	circuitStateClosed CircuitState = iota
	circuitStateOpen
	circuitStateHalfOpen

	// Circuit breaker defaults
	defaultFailureThreshold = 5
	defaultSuccessThreshold = 2
	defaultTimeout          = 30 * time.Second
	defaultHalfOpenRequests = 3
)

// CircuitState represents the state of a circuit breaker
type CircuitState int

// String returns a human-readable representation of the CircuitState.
func (s CircuitState) String() string {
	switch s {
	case circuitStateClosed:
		return "closed"
	case circuitStateOpen:
		return "open"
	case circuitStateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreaker implements the circuit breaker pattern for callbacks
type CircuitBreaker struct {
	mu               sync.RWMutex
	state            CircuitState
	failures         int
	successes        int
	lastFailureTime  time.Time
	failureThreshold int
	successThreshold int
	timeout          time.Duration
	halfOpenRequests int
	halfOpenAttempts int
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(failureThreshold, successThreshold int, timeout time.Duration) *CircuitBreaker {
	if failureThreshold <= 0 {
		failureThreshold = defaultFailureThreshold
	}
	if successThreshold <= 0 {
		successThreshold = defaultSuccessThreshold
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	return &CircuitBreaker{
		state:            circuitStateClosed,
		failureThreshold: failureThreshold,
		successThreshold: successThreshold,
		timeout:          timeout,
		halfOpenRequests: defaultHalfOpenRequests,
	}
}

// CanExecute checks if the circuit breaker allows execution
func (cb *CircuitBreaker) CanExecute() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	switch cb.state {
	case circuitStateClosed:
		return true
	case circuitStateOpen:
		// Check if timeout has passed
		if time.Since(cb.lastFailureTime) > cb.timeout {
			return true // Will transition to half-open
		}
		return false
	case circuitStateHalfOpen:
		// Allow limited requests in half-open state
		return cb.halfOpenAttempts < cb.halfOpenRequests
	default:
		return false
	}
}

// RecordSuccess records a successful execution
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures = 0

	switch cb.state {
	case circuitStateHalfOpen:
		cb.successes++
		if cb.successes >= cb.successThreshold {
			cb.state = circuitStateClosed
			cb.successes = 0
			cb.halfOpenAttempts = 0
			slog.Info("circuit breaker closed")
		}
	case circuitStateClosed:
		// Already closed, nothing to do
	}
}

// RecordFailure records a failed execution
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailureTime = time.Now()

	switch cb.state {
	case circuitStateClosed:
		if cb.failures >= cb.failureThreshold {
			cb.state = circuitStateOpen
			slog.Warn("circuit breaker opened",
				"failures", cb.failures,
				"threshold", cb.failureThreshold)
		}
	case circuitStateHalfOpen:
		cb.state = circuitStateOpen
		cb.successes = 0
		cb.halfOpenAttempts = 0
		slog.Warn("circuit breaker reopened from half-open")
	}
}

// GetState returns the current circuit breaker state
func (cb *CircuitBreaker) GetState() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// transitionToHalfOpen transitions from open to half-open if timeout passed
func (cb *CircuitBreaker) transitionToHalfOpen() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == circuitStateOpen && time.Since(cb.lastFailureTime) > cb.timeout {
		cb.state = circuitStateHalfOpen
		cb.successes = 0
		cb.failures = 0
		cb.halfOpenAttempts = 0
		slog.Info("circuit breaker transitioned to half-open")
	}
}

// IncrementHalfOpenAttempts increments the half-open attempt counter
func (cb *CircuitBreaker) IncrementHalfOpenAttempts() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.state == circuitStateHalfOpen {
		cb.halfOpenAttempts++
	}
}

// CacheMetrics tracks cache performance metrics using lock-free atomic operations
// to minimize contention under high concurrency.
type CacheMetrics struct {
	hits         atomic.Int64
	misses       atomic.Int64
	errors       atomic.Int64
	evictions    atomic.Int64
	totalLatency atomic.Int64 // nanoseconds
	requests     atomic.Int64
}

// RecordHit records a cache hit with the observed lookup latency.
func (m *CacheMetrics) RecordHit(latency time.Duration) {
	m.hits.Add(1)
	m.requests.Add(1)
	m.totalLatency.Add(int64(latency))
}

// RecordMiss records a cache miss.
func (m *CacheMetrics) RecordMiss() {
	m.misses.Add(1)
	m.requests.Add(1)
}

// RecordError records a cache error.
func (m *CacheMetrics) RecordError() {
	m.errors.Add(1)
}

// RecordEviction records a cache eviction.
func (m *CacheMetrics) RecordEviction() {
	m.evictions.Add(1)
}

// GetStats returns current cache statistics as a snapshot.
func (m *CacheMetrics) GetStats() map[string]interface{} {
	hits := m.hits.Load()
	misses := m.misses.Load()
	errs := m.errors.Load()
	evictions := m.evictions.Load()
	requests := m.requests.Load()
	totalLatency := m.totalLatency.Load()

	hitRate := 0.0
	if requests > 0 {
		hitRate = float64(hits) / float64(requests) * 100
	}

	avgLatency := time.Duration(0)
	if requests > 0 {
		avgLatency = time.Duration(totalLatency) / time.Duration(requests)
	}

	return map[string]interface{}{
		"hits":        hits,
		"misses":      misses,
		"errors":      errs,
		"evictions":   evictions,
		"requests":    requests,
		"hit_rate":    hitRate,
		"avg_latency": avgLatency.String(),
	}
}

// CachedResponse represents a cached callback response
type CachedResponse struct {
	Data      map[string]any `json:"data"`
	Timestamp time.Time      `json:"timestamp"`
	ExpiresAt time.Time      `json:"expires_at"`
}

// CallbackCache provides caching functionality for callbacks
type CallbackCache struct {
	cache           cacher.Cacher
	circuitBreakers map[string]*CircuitBreaker
	metrics         *CacheMetrics
	mu              sync.RWMutex
}

// NewCallbackCache creates a new callback cache
func NewCallbackCache(cache cacher.Cacher) *CallbackCache {
	return &CallbackCache{
		cache:           cache,
		circuitBreakers: make(map[string]*CircuitBreaker),
		metrics:         &CacheMetrics{},
	}
}

// Get retrieves a cached callback response
func (cc *CallbackCache) Get(ctx context.Context, cacheKey string) (map[string]any, bool, error) {
	start := time.Now()

	reader, err := cc.cache.Get(ctx, callbackCacheType, cacheKey)
	if err != nil {
		if err == cacher.ErrNotFound {
			cc.metrics.RecordMiss()
			return nil, false, nil
		}
		cc.metrics.RecordError()
		slog.Error("failed to get from cache",
			"cache_key", cacheKey,
			"error", err)
		return nil, false, err
	}

	if reader == nil {
		cc.metrics.RecordMiss()
		return nil, false, nil
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		cc.metrics.RecordError()
		slog.Error("failed to read cached data",
			"cache_key", cacheKey,
			"error", err)
		return nil, false, err
	}

	var cached CachedResponse
	if err := json.Unmarshal(data, &cached); err != nil {
		cc.metrics.RecordError()
		slog.Error("failed to unmarshal cached response",
			"cache_key", cacheKey,
			"error", err)
		return nil, false, err
	}

	// Check if expired
	if time.Now().After(cached.ExpiresAt) {
		cc.metrics.RecordMiss()
		cc.metrics.RecordEviction()
		// Delete expired entry
		go func() {
			deleteCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := cc.cache.Delete(deleteCtx, callbackCacheType, cacheKey); err != nil {
				slog.Error("failed to delete expired cache entry",
					"cache_key", cacheKey,
					"error", err)
			}
		}()
		return nil, false, nil
	}

	cc.metrics.RecordHit(time.Since(start))
	slog.Debug("cache hit",
		"cache_key", cacheKey,
		"age", time.Since(cached.Timestamp))

	return cached.Data, true, nil
}

// Put stores a callback response in the cache
func (cc *CallbackCache) Put(ctx context.Context, cacheKey string, data map[string]any, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("invalid TTL: %v", ttl)
	}

	cached := CachedResponse{
		Data:      data,
		Timestamp: time.Now(),
		ExpiresAt: time.Now().Add(ttl),
	}

	jsonData, err := json.Marshal(cached)
	if err != nil {
		cc.metrics.RecordError()
		slog.Error("failed to marshal response for caching",
			"cache_key", cacheKey,
			"error", err)
		return err
	}

	if err := cc.cache.PutWithExpires(ctx, callbackCacheType, cacheKey, bytes.NewReader(jsonData), ttl); err != nil {
		cc.metrics.RecordError()
		slog.Error("failed to put in cache",
			"cache_key", cacheKey,
			"error", err)
		return err
	}

	slog.Debug("cached callback response",
		"cache_key", cacheKey,
		"ttl", ttl)

	return nil
}

// Invalidate removes a cached entry
func (cc *CallbackCache) Invalidate(ctx context.Context, cacheKey string) error {
	if err := cc.cache.Delete(ctx, callbackCacheType, cacheKey); err != nil {
		slog.Error("failed to invalidate cache entry",
			"cache_key", cacheKey,
			"error", err)
		return err
	}

	cc.metrics.RecordEviction()
	slog.Debug("invalidated cache entry",
		"cache_key", cacheKey)

	return nil
}

// InvalidatePattern removes all cached entries matching a pattern
func (cc *CallbackCache) InvalidatePattern(ctx context.Context, pattern string) error {
	if err := cc.cache.DeleteByPattern(ctx, callbackCacheType, pattern); err != nil {
		slog.Error("failed to invalidate cache pattern",
			"pattern", pattern,
			"error", err)
		return err
	}

	slog.Info("invalidated cache pattern",
		"pattern", pattern)

	return nil
}

// GetCircuitBreaker gets or creates a circuit breaker for a callback
func (cc *CallbackCache) GetCircuitBreaker(cacheKey string) *CircuitBreaker {
	cc.mu.RLock()
	cb, exists := cc.circuitBreakers[cacheKey]
	cc.mu.RUnlock()

	if exists {
		return cb
	}

	cc.mu.Lock()
	defer cc.mu.Unlock()

	// Double-check after acquiring write lock
	if cb, exists = cc.circuitBreakers[cacheKey]; exists {
		return cb
	}

	cb = NewCircuitBreaker(defaultFailureThreshold, defaultSuccessThreshold, defaultTimeout)
	cc.circuitBreakers[cacheKey] = cb

	slog.Debug("created circuit breaker",
		"cache_key", cacheKey)

	return cb
}

// GetMetrics returns the cache metrics
func (cc *CallbackCache) GetMetrics() map[string]interface{} {
	return cc.metrics.GetStats()
}

// Cleanup removes expired circuit breakers (should be called periodically)
func (cc *CallbackCache) Cleanup() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	// Remove circuit breakers that have been closed for a while
	for key, cb := range cc.circuitBreakers {
		if cb.GetState() == circuitStateClosed && cb.failures == 0 && time.Since(cb.lastFailureTime) > 10*time.Minute {
			delete(cc.circuitBreakers, key)
		}
	}
}

// CachedFetchResponse represents a cached FetchResponse
type CachedFetchResponse struct {
	Body        []byte              `json:"body"`
	Headers     map[string][]string `json:"headers"`
	StatusCode  int                 `json:"status_code"`
	ContentType string              `json:"content_type"`
	Timestamp   time.Time           `json:"timestamp"`
	ExpiresAt   time.Time           `json:"expires_at"`
}

// GetFetch retrieves a cached FetchResponse
func (cc *CallbackCache) GetFetch(ctx context.Context, cacheKey string) (*FetchResponse, bool, error) {
	start := time.Now()

	reader, err := cc.cache.Get(ctx, callbackCacheType, cacheKey)
	if err != nil {
		if err == cacher.ErrNotFound {
			cc.metrics.RecordMiss()
			return nil, false, nil
		}
		cc.metrics.RecordError()
		slog.Error("failed to get fetch from cache",
			"cache_key", cacheKey,
			"error", err)
		return nil, false, err
	}

	if reader == nil {
		cc.metrics.RecordMiss()
		return nil, false, nil
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		cc.metrics.RecordError()
		slog.Error("failed to read cached fetch data",
			"cache_key", cacheKey,
			"error", err)
		return nil, false, err
	}

	var cached CachedFetchResponse
	if err := json.Unmarshal(data, &cached); err != nil {
		cc.metrics.RecordError()
		slog.Error("failed to unmarshal cached fetch response",
			"cache_key", cacheKey,
			"error", err)
		return nil, false, err
	}

	// Check if expired
	if time.Now().After(cached.ExpiresAt) {
		cc.metrics.RecordMiss()
		cc.metrics.RecordEviction()
		// Delete expired entry
		go func() {
			deleteCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := cc.cache.Delete(deleteCtx, callbackCacheType, cacheKey); err != nil {
				slog.Error("failed to delete expired cache entry",
					"cache_key", cacheKey,
					"error", err)
			}
		}()
		return nil, false, nil
	}

	cc.metrics.RecordHit(time.Since(start))
	slog.Debug("cache hit for fetch",
		"cache_key", cacheKey,
		"age", time.Since(cached.Timestamp))

	// Convert headers map to http.Header
	headers := make(http.Header)
	for k, v := range cached.Headers {
		headers[k] = v
	}

	return &FetchResponse{
		Body:        cached.Body,
		Headers:     headers,
		StatusCode:  cached.StatusCode,
		ContentType: cached.ContentType,
	}, true, nil
}

// PutFetch stores a FetchResponse in the cache
func (cc *CallbackCache) PutFetch(ctx context.Context, cacheKey string, fetchResp *FetchResponse, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("invalid TTL: %v", ttl)
	}

	// Convert headers to map
	headersMap := make(map[string][]string)
	for k, v := range fetchResp.Headers {
		headersMap[k] = v
	}

	cached := CachedFetchResponse{
		Body:        fetchResp.Body,
		Headers:     headersMap,
		StatusCode:  fetchResp.StatusCode,
		ContentType: fetchResp.ContentType,
		Timestamp:   time.Now(),
		ExpiresAt:   time.Now().Add(ttl),
	}

	jsonData, err := json.Marshal(cached)
	if err != nil {
		cc.metrics.RecordError()
		slog.Error("failed to marshal fetch response for caching",
			"cache_key", cacheKey,
			"error", err)
		return err
	}

	if err := cc.cache.PutWithExpires(ctx, callbackCacheType, cacheKey, bytes.NewReader(jsonData), ttl); err != nil {
		cc.metrics.RecordError()
		slog.Error("failed to put fetch in cache",
			"cache_key", cacheKey,
			"error", err)
		return err
	}

	slog.Debug("cached fetch response",
		"cache_key", cacheKey,
		"ttl", ttl)

	return nil
}
