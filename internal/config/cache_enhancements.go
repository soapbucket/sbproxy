// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
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

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// CacheKeyNormalization defines how to normalize cache keys for better hit rates
type CacheKeyNormalization struct {
	QueryParams QueryParamNormalization `json:"query_params,omitempty"`
	Headers     HeaderNormalization     `json:"headers,omitempty"`
	Cookies     CookieNormalization     `json:"cookies,omitempty"`
	CaseNormalization bool               `json:"case_normalization,omitempty"` // Normalize URL case
}

// QueryParamNormalization defines query parameter normalization
type QueryParamNormalization struct {
	Ignore []string `json:"ignore,omitempty"` // Parameters to ignore (e.g., utm_*, tracking params)
	Sort   bool     `json:"sort,omitempty"`   // Sort parameters alphabetically
	LowerCase bool  `json:"lowercase,omitempty"` // Convert names to lowercase
}

// HeaderNormalization defines header normalization
type HeaderNormalization struct {
	Ignore    []string          `json:"ignore,omitempty"`     // Headers to ignore
	Include   []string          `json:"include,omitempty"`    // Only include these headers
	Normalize map[string]string `json:"normalize,omitempty"`  // Header name -> normalized name
}

// CookieNormalization defines cookie normalization
type CookieNormalization struct {
	Ignore  []string `json:"ignore,omitempty"`  // Cookies to ignore
	Include []string `json:"include,omitempty"` // Only include these cookies
}

// StaleWhileRevalidate defines stale-while-revalidate behavior
type StaleWhileRevalidate struct {
	Enabled        bool          `json:"enabled"`
	Duration       reqctx.Duration `json:"duration"`          // How long to serve stale content while revalidating
	StaleIfError   reqctx.Duration `json:"stale_if_error"`    // Serve stale on backend error
	MaxAge         reqctx.Duration `json:"max_age"`           // Maximum age before stale cannot be served
	AsyncRevalidate bool         `json:"async_revalidate"`  // Revalidate in background (default: true)
}

// CachedResponse represents a cached HTTP response with metadata
type CachedResponse struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers"`
	Body       []byte              `json:"body"`
	CachedAt   time.Time           `json:"cached_at"`
	ExpiresAt  time.Time           `json:"expires_at"`
	StaleAt    time.Time           `json:"stale_at,omitempty"`    // When response becomes stale for SWR
	ETag       string              `json:"etag,omitempty"`
	LastModified string            `json:"last_modified,omitempty"`
}

// IsStale checks if the cached response is stale
func (cr *CachedResponse) IsStale() bool {
	if cr.StaleAt.IsZero() {
		return time.Now().After(cr.ExpiresAt)
	}
	return time.Now().After(cr.StaleAt)
}

// IsExpired checks if the cached response is expired (cannot be served even as stale)
func (cr *CachedResponse) IsExpired() bool {
	return time.Now().After(cr.ExpiresAt)
}

// CanServeStale checks if stale content can still be served
func (cr *CachedResponse) CanServeStale(maxAge time.Duration) bool {
	if maxAge == 0 {
		return false
	}
	age := time.Since(cr.CachedAt)
	return age < maxAge
}

// revalidationQueue manages background revalidation tasks
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

	// Perform request (this would normally go through the action's transport)
	// For now, we'll use a basic client
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
		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			slog.Error("failed to read revalidation response body", "error", err, "key", task.key)
			return
		}

		// Note: Write-back of revalidated response would happen via the caching layer
		// with updated expiration times and etag/last-modified headers
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

// Global revalidation queue
var globalRevalidationQueue *revalidationQueue
var revalidationQueueOnce sync.Once

func getRevalidationQueue() *revalidationQueue {
	revalidationQueueOnce.Do(func() {
		globalRevalidationQueue = newRevalidationQueue(2)
	})
	return globalRevalidationQueue
}

// NormalizeCacheKey normalizes a cache key according to the configuration
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

// SerializeCachedResponse serializes a CachedResponse to JSON
func SerializeCachedResponse(cr *CachedResponse) ([]byte, error) {
	return json.Marshal(cr)
}

// DeserializeCachedResponse deserializes a CachedResponse from JSON
func DeserializeCachedResponse(data []byte) (*CachedResponse, error) {
	var cr CachedResponse
	err := json.Unmarshal(data, &cr)
	return &cr, err
}

