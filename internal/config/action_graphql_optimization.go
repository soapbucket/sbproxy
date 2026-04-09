// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

const (
	// DefaultResultCacheSize is the default value for result cache size.
	DefaultResultCacheSize = 1000
	// DefaultResultCacheTTL is the default value for result cache ttl.
	DefaultResultCacheTTL  = 5 * time.Minute
	// DefaultMaxBatchSize is the default value for max batch size.
	DefaultMaxBatchSize    = 10
)

// resultCache caches GraphQL query results
type resultCache struct {
	cache   map[string]*cachedResult
	maxSize int
	ttl     time.Duration
	mu      sync.RWMutex
}

type cachedResult struct {
	data      []byte
	cached    time.Time
	expiresAt time.Time
}

func newResultCache(size int, ttl time.Duration) *resultCache {
	if size == 0 {
		size = DefaultResultCacheSize
	}
	if ttl == 0 {
		ttl = DefaultResultCacheTTL
	}

	c := &resultCache{
		cache:   make(map[string]*cachedResult),
		maxSize: size,
		ttl:     ttl,
	}

	// Start cleanup goroutine
	go c.cleanupLoop()

	return c
}

// Get retrieves a value from the resultCache.
func (c *resultCache) Get(key string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.cache[key]
	if !exists {
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		return nil, false
	}

	return entry.data, true
}

// Set stores a value in the resultCache.
func (c *resultCache) Set(key string, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict oldest entries if cache is full
	if len(c.cache) >= c.maxSize {
		c.evictOldest()
	}

	c.cache[key] = &cachedResult{
		data:      data,
		cached:    time.Now(),
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *resultCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	first := true

	for key, entry := range c.cache {
		if first || entry.cached.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.cached
			first = false
		}
	}

	if oldestKey != "" {
		delete(c.cache, oldestKey)
	}
}

func (c *resultCache) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.cleanup()
	}
}

func (c *resultCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.cache {
		if now.After(entry.expiresAt) {
			delete(c.cache, key)
		}
	}
}

// generateCacheKey generates a cache key from query and variables
func generateCacheKey(query string, variables map[string]interface{}) string {
	h := sha256.New()
	h.Write([]byte(query))

	// Include variables in hash if present
	if len(variables) > 0 {
		// Sort variables for consistent hashing
		keys := make([]string, 0, len(variables))
		for k := range variables {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			h.Write([]byte(k))
			if v, err := json.Marshal(variables[k]); err == nil {
				h.Write(v)
			}
		}
	}

	return hex.EncodeToString(h.Sum(nil))
}

// batchRequest represents a batched GraphQL request
type batchRequest struct {
	requests []*GraphQLRequest
	indices  []int // Original indices for deduplication
}

// parseBatchRequest parses a batch GraphQL request
func parseBatchRequest(body []byte) ([]*GraphQLRequest, error) {
	// Try to parse as array first (batch)
	var batch []*GraphQLRequest
	if err := json.Unmarshal(body, &batch); err == nil && len(batch) > 0 {
		return batch, nil
	}

	// Try to parse as single request
	var single GraphQLRequest
	if err := json.Unmarshal(body, &single); err == nil {
		return []*GraphQLRequest{&single}, nil
	}

	return nil, fmt.Errorf("invalid GraphQL request format")
}

// deduplicateQueries removes duplicate queries from a batch
func deduplicateQueries(requests []*GraphQLRequest) ([]*GraphQLRequest, []int, map[int]int) {
	// Map from query hash to first occurrence index
	seen := make(map[string]int)
	deduplicated := make([]*GraphQLRequest, 0)
	indices := make([]int, 0)
	indexMap := make(map[int]int) // original index -> deduplicated index

	for i, req := range requests {
		key := generateCacheKey(req.Query, req.Variables)
		if existingIdx, exists := seen[key]; exists {
			// Duplicate found, map to existing index
			indexMap[i] = existingIdx
		} else {
			// New query
			seen[key] = len(deduplicated)
			indexMap[i] = len(deduplicated)
			deduplicated = append(deduplicated, req)
			indices = append(indices, i)
		}
	}

	return deduplicated, indices, indexMap
}

// expandBatchResponse expands a batch response back to original size using deduplication map
func expandBatchResponse(batchResp []*GraphQLResponse, indexMap map[int]int) []*GraphQLResponse {
	if len(indexMap) == 0 {
		return batchResp
	}

	expanded := make([]*GraphQLResponse, len(indexMap))
	for origIdx, dedupIdx := range indexMap {
		if dedupIdx < len(batchResp) {
			expanded[origIdx] = batchResp[dedupIdx]
		}
	}

	return expanded
}

// GraphQLResponse represents a GraphQL response
type GraphQLResponse struct {
	Data       interface{}            `json:"data,omitempty"`
	Errors     []interface{}          `json:"errors,omitempty"`
	Extensions map[string]interface{} `json:"extensions,omitempty"`
}

// addOptimizationHints adds optimization hints to a GraphQL response
func addOptimizationHints(resp *GraphQLResponse, hints map[string]interface{}) {
	if resp.Extensions == nil {
		resp.Extensions = make(map[string]interface{})
	}

	if resp.Extensions["optimization"] == nil {
		resp.Extensions["optimization"] = make(map[string]interface{})
	}

	optHints := resp.Extensions["optimization"].(map[string]interface{})
	for k, v := range hints {
		optHints[k] = v
	}
}

// processBatchRequest processes a batch GraphQL request with optimization
func (t *graphqlTransport) processBatchRequest(r *http.Request, requests []*GraphQLRequest) (*http.Response, error) {
	start := time.Now()
	configID := "unknown"
	if requestData := reqctx.GetRequestData(r.Context()); requestData != nil && requestData.Config != nil {
		configData := reqctx.ConfigParams(requestData.Config)
		if id := configData.GetConfigID(); id != "" {
			configID = id
		}
	}

	// Deduplicate queries if enabled
	var deduplicated []*GraphQLRequest
	var indexMap map[int]int
	var dedupCount int

	if t.config.EnableQueryDeduplication && len(requests) > 1 {
		deduplicated, _, indexMap = deduplicateQueries(requests)
		dedupCount = len(requests) - len(deduplicated)
		slog.Debug("graphql: batch deduplication", "original", len(requests), "deduplicated", len(deduplicated), "removed", dedupCount)
	} else {
		deduplicated = requests
		indexMap = make(map[int]int)
		for i := range requests {
			indexMap[i] = i
		}
	}

	// Check batch size limit
	if len(deduplicated) > t.config.MaxBatchSize {
		return t.errorResponse(r, fmt.Sprintf("Batch size %d exceeds maximum %d", len(deduplicated), t.config.MaxBatchSize), "BATCH_TOO_LARGE", http.StatusBadRequest)
	}

	// Process each query in batch
	responses := make([]*GraphQLResponse, 0, len(deduplicated))
	cacheHits := 0

	for i, req := range deduplicated {
		var resp *GraphQLResponse
		var cached bool

		// Check result cache if enabled
		if t.config.EnableResultCaching && t.config.resultCache != nil {
			cacheKey := generateCacheKey(req.Query, req.Variables)
			if cachedData, found := t.config.resultCache.Get(cacheKey); found {
				if err := json.Unmarshal(cachedData, &resp); err == nil {
					cached = true
					cacheHits++
					slog.Debug("graphql: result cache hit", "query_index", i)
				}
			}
		}

		// If not cached, process query
		if !cached {
			queryResp, err := t.processSingleQuery(r, req)
			if err != nil {
				// Create error response
				resp = &GraphQLResponse{
					Errors: []interface{}{
						map[string]interface{}{
							"message": err.Error(),
							"extensions": map[string]string{
								"code": "EXECUTION_ERROR",
							},
						},
					},
				}
			} else {
				// Parse response
				respBody, err := io.ReadAll(queryResp.Body)
				queryResp.Body.Close()
				if err != nil {
					resp = &GraphQLResponse{
						Errors: []interface{}{
							map[string]interface{}{
								"message": "Failed to read response",
								"extensions": map[string]string{
									"code": "INTERNAL_ERROR",
								},
							},
						},
					}
				} else {
					if err := json.Unmarshal(respBody, &resp); err != nil {
						resp = &GraphQLResponse{
							Errors: []interface{}{
								map[string]interface{}{
									"message": "Invalid response format",
									"extensions": map[string]string{
										"code": "INVALID_RESPONSE",
									},
								},
							},
						}
					} else {
						// Cache successful responses
						if t.config.EnableResultCaching && t.config.resultCache != nil && resp.Errors == nil {
							cacheKey := generateCacheKey(req.Query, req.Variables)
							if respData, err := json.Marshal(resp); err == nil {
								t.config.resultCache.Set(cacheKey, respData)
							}
						}
					}
				}
			}
		}

		// Add optimization hints if enabled
		if t.config.EnableOptimizationHints {
			hints := map[string]interface{}{
				"cached":      cached,
				"query_index": i,
			}
			if dedupCount > 0 {
				hints["deduplicated"] = true
			}
			addOptimizationHints(resp, hints)
		}

		responses = append(responses, resp)
	}

	// Expand responses if deduplication was used
	if len(indexMap) > 0 && len(indexMap) != len(responses) {
		responses = expandBatchResponse(responses, indexMap)
	}

	// Create batch response
	batchRespBody, err := json.Marshal(responses)
	if err != nil {
		return t.errorResponse(r, "Failed to marshal batch response", "INTERNAL_ERROR", http.StatusInternalServerError)
	}

	duration := time.Since(start)
	slog.Info("graphql: batch processed",
		"total_queries", len(requests),
		"deduplicated", len(deduplicated),
		"cache_hits", cacheHits,
		"duration_ms", duration.Milliseconds())

	// Record metrics
	metric.GraphQLBatchSize(configID, len(requests), len(deduplicated))
	if cacheHits > 0 {
		metric.GraphQLCacheHit(configID, cacheHits)
	}

	return &http.Response{
		Status:        http.StatusText(http.StatusOK),
		StatusCode:    http.StatusOK,
		Proto:         r.Proto,
		ProtoMajor:    r.ProtoMajor,
		ProtoMinor:    r.ProtoMinor,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(strings.NewReader(string(batchRespBody))),
		ContentLength: int64(len(batchRespBody)),
		Request:       r,
	}, nil
}

// processSingleQuery processes a single GraphQL query
// This reuses the existing validation and processing logic from RoundTrip
func (t *graphqlTransport) processSingleQuery(r *http.Request, gqlReq *GraphQLRequest) (*http.Response, error) {
	// Create a new request with just this query for processing
	reqBody, err := json.Marshal(gqlReq)
	if err != nil {
		return t.errorResponse(r, "Failed to marshal request", "INTERNAL_ERROR", http.StatusInternalServerError)
	}

	// Create a cloned request for this single query
	singleReq := r.Clone(r.Context())
	singleReq.Body = io.NopCloser(strings.NewReader(string(reqBody)))
	singleReq.ContentLength = int64(len(reqBody))
	singleReq.Header.Set("Content-Length", strconv.Itoa(len(reqBody)))

	// Temporarily disable batching to avoid recursion
	originalBatching := t.config.EnableQueryBatching
	t.config.EnableQueryBatching = false
	defer func() {
		t.config.EnableQueryBatching = originalBatching
	}()

	// Process using existing RoundTrip logic
	return t.RoundTrip(singleReq)
}
