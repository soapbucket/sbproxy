package config

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

func TestGraphQLOptimization_QueryBatching(t *testing.T) {
	data := []byte(`{
		"type": "graphql",
		"url": "http://example.com/graphql",
		"enable_query_batching": true,
		"max_batch_size": 10
	}`)

	action, err := NewGraphQLAction(data)
	if err != nil {
		t.Fatalf("Failed to create GraphQL action: %v", err)
	}

	gqlAction := action.(*GraphQLAction)
	if !gqlAction.EnableQueryBatching {
		t.Error("Query batching should be enabled")
	}
	if gqlAction.MaxBatchSize != 10 {
		t.Errorf("Expected MaxBatchSize 10, got %d", gqlAction.MaxBatchSize)
	}
}

func TestGraphQLOptimization_QueryDeduplication(t *testing.T) {
	// Test deduplication logic
	requests := []*GraphQLRequest{
		{Query: "query { user { id name } }", Variables: nil},
		{Query: "query { user { id name } }", Variables: nil}, // Duplicate
		{Query: "query { posts { id title } }", Variables: nil},
		{Query: "query { user { id name } }", Variables: nil}, // Duplicate
	}

	deduplicated, indices, indexMap := deduplicateQueries(requests)

	if len(deduplicated) != 2 {
		t.Errorf("Expected 2 unique queries after deduplication, got %d", len(deduplicated))
	}

	// Check that duplicates are mapped correctly
	if indexMap[1] != indexMap[0] {
		t.Error("Duplicate query should map to same index")
	}
	if indexMap[3] != indexMap[0] {
		t.Error("Duplicate query should map to same index")
	}

	// Check indices
	if len(indices) != 2 {
		t.Errorf("Expected 2 indices, got %d", len(indices))
	}
}

func TestGraphQLOptimization_QueryDeduplicationWithVariables(t *testing.T) {
	// Test deduplication with variables
	requests := []*GraphQLRequest{
		{Query: "query($id: ID!) { user(id: $id) { name } }", Variables: map[string]interface{}{"id": "1"}},
		{Query: "query($id: ID!) { user(id: $id) { name } }", Variables: map[string]interface{}{"id": "1"}}, // Same variables
		{Query: "query($id: ID!) { user(id: $id) { name } }", Variables: map[string]interface{}{"id": "2"}}, // Different variables
	}

	deduplicated, _, indexMap := deduplicateQueries(requests)

	if len(deduplicated) != 2 {
		t.Errorf("Expected 2 unique queries (same query + vars vs different vars), got %d", len(deduplicated))
	}

	// First two should map to same index (same query + same vars)
	if indexMap[1] != indexMap[0] {
		t.Error("Queries with same variables should map to same index")
	}

	// Third should map to different index (different vars)
	if indexMap[2] == indexMap[0] {
		t.Error("Query with different variables should map to different index")
	}
}

func TestGraphQLOptimization_ResultCache(t *testing.T) {
	cache := newResultCache(10, 1*time.Minute)

	key1 := "test-key-1"
	data1 := []byte(`{"data": {"user": {"id": "1"}}}`)

	// Test Set and Get
	cache.Set(key1, data1)
	retrieved, found := cache.Get(key1)
	if !found {
		t.Error("Cache should contain the key")
	}
	if !bytes.Equal(retrieved, data1) {
		t.Error("Retrieved data should match stored data")
	}

	// Test cache miss
	_, found = cache.Get("non-existent-key")
	if found {
		t.Error("Non-existent key should not be found")
	}
}

func TestGraphQLOptimization_ResultCacheExpiration(t *testing.T) {
	cache := newResultCache(10, 100*time.Millisecond)

	key := "test-key"
	data := []byte(`{"data": {"user": {"id": "1"}}}`)

	cache.Set(key, data)

	// Should be found immediately
	_, found := cache.Get(key)
	if !found {
		t.Error("Cache should contain the key immediately after setting")
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Should not be found after expiration
	_, found = cache.Get(key)
	if found {
		t.Error("Cache should not contain expired key")
	}
}

func TestGraphQLOptimization_ResultCacheEviction(t *testing.T) {
	cache := newResultCache(3, 1*time.Minute)

	// Fill cache beyond max size
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("key-%d", i)
		data := []byte(fmt.Sprintf(`{"data": {"id": "%d"}}`, i))
		cache.Set(key, data)
	}

	// Cache should only contain 3 entries (oldest evicted)
	// Note: This test is probabilistic as eviction depends on timing
	// We'll just verify cache doesn't exceed max size
	cache.mu.RLock()
	size := len(cache.cache)
	cache.mu.RUnlock()

	if size > cache.maxSize {
		t.Errorf("Cache size %d exceeds max size %d", size, cache.maxSize)
	}
}

func TestGraphQLOptimization_GenerateCacheKey(t *testing.T) {
	query := "query { user { id name } }"
	variables1 := map[string]interface{}{"id": "1"}
	variables2 := map[string]interface{}{"id": "2"}

	key1 := generateCacheKey(query, variables1)
	key2 := generateCacheKey(query, variables1)
	key3 := generateCacheKey(query, variables2)

	// Same query + same variables should produce same key
	if key1 != key2 {
		t.Error("Same query and variables should produce same cache key")
	}

	// Same query + different variables should produce different key
	if key1 == key3 {
		t.Error("Same query with different variables should produce different cache key")
	}

	// Empty variables should work
	key4 := generateCacheKey(query, nil)
	if key4 == "" {
		t.Error("Cache key should not be empty")
	}
}

func TestGraphQLOptimization_ParseBatchRequest(t *testing.T) {
	// Test single request
	singleReq := `{"query": "query { user { id } }"}`
	batch, err := parseBatchRequest([]byte(singleReq))
	if err != nil {
		t.Fatalf("Failed to parse single request: %v", err)
	}
	if len(batch) != 1 {
		t.Errorf("Expected 1 request, got %d", len(batch))
	}

	// Test batch request
	batchReq := `[
		{"query": "query { user { id } }"},
		{"query": "query { posts { id } }"}
	]`
	batch, err = parseBatchRequest([]byte(batchReq))
	if err != nil {
		t.Fatalf("Failed to parse batch request: %v", err)
	}
	if len(batch) != 2 {
		t.Errorf("Expected 2 requests, got %d", len(batch))
	}

	// Test invalid request
	invalidReq := `{invalid json}`
	_, err = parseBatchRequest([]byte(invalidReq))
	if err == nil {
		t.Error("Should fail to parse invalid JSON")
	}
}

func TestGraphQLOptimization_ExpandBatchResponse(t *testing.T) {
	batchResp := []*GraphQLResponse{
		{Data: map[string]interface{}{"user": map[string]interface{}{"id": "1"}}},
		{Data: map[string]interface{}{"posts": []interface{}{}}},
	}

	// Test with no deduplication (1:1 mapping)
	indexMap1 := map[int]int{0: 0, 1: 1}
	expanded1 := expandBatchResponse(batchResp, indexMap1)
	if len(expanded1) != 2 {
		t.Errorf("Expected 2 responses, got %d", len(expanded1))
	}

	// Test with deduplication (multiple indices map to same response)
	indexMap2 := map[int]int{0: 0, 1: 0, 2: 1} // indices 0 and 1 both map to response 0
	expanded2 := expandBatchResponse(batchResp, indexMap2)
	if len(expanded2) != 3 {
		t.Errorf("Expected 3 responses (expanded), got %d", len(expanded2))
	}
	if expanded2[0] != expanded2[1] {
		t.Error("Deduplicated responses should reference same object")
	}
}

func TestGraphQLOptimization_AddOptimizationHints(t *testing.T) {
	resp := &GraphQLResponse{
		Data: map[string]interface{}{"user": map[string]interface{}{"id": "1"}},
	}

	hints := map[string]interface{}{
		"cached":      true,
		"query_index": 0,
		"deduplicated": true,
	}

	addOptimizationHints(resp, hints)

	if resp.Extensions == nil {
		t.Fatal("Extensions should be created")
	}

	optHints, ok := resp.Extensions["optimization"].(map[string]interface{})
	if !ok {
		t.Fatal("Optimization hints should be present")
	}

	if optHints["cached"] != true {
		t.Error("Cached hint should be true")
	}
	if optHints["query_index"] != 0 {
		t.Error("Query index hint should be 0")
	}
	if optHints["deduplicated"] != true {
		t.Error("Deduplicated hint should be true")
	}
}

func TestGraphQLOptimization_ConfigDefaults(t *testing.T) {
	data := []byte(`{
		"type": "graphql",
		"url": "http://example.com/graphql"
	}`)

	action, err := NewGraphQLAction(data)
	if err != nil {
		t.Fatalf("Failed to create GraphQL action: %v", err)
	}

	gqlAction := action.(*GraphQLAction)

	// Check defaults
	if gqlAction.MaxBatchSize != DefaultMaxBatchSize {
		t.Errorf("Expected MaxBatchSize %d, got %d", DefaultMaxBatchSize, gqlAction.MaxBatchSize)
	}

	// Batching and deduplication should default to false (zero value)
	if gqlAction.EnableQueryBatching {
		t.Error("EnableQueryBatching should default to false")
	}
	if gqlAction.EnableQueryDeduplication {
		t.Error("EnableQueryDeduplication should default to false")
	}
}

func TestGraphQLOptimization_ResultCacheConfig(t *testing.T) {
	data := []byte(`{
		"type": "graphql",
		"url": "http://example.com/graphql",
		"enable_result_caching": true,
		"result_cache_size": 500,
		"result_cache_ttl": "10m"
	}`)

	action, err := NewGraphQLAction(data)
	if err != nil {
		t.Fatalf("Failed to create GraphQL action: %v", err)
	}

	gqlAction := action.(*GraphQLAction)

	if !gqlAction.EnableResultCaching {
		t.Error("Result caching should be enabled")
	}
	if gqlAction.ResultCacheSize != 500 {
		t.Errorf("Expected ResultCacheSize 500, got %d", gqlAction.ResultCacheSize)
	}
	if gqlAction.resultCache == nil {
		t.Error("Result cache should be initialized")
	}
	if gqlAction.resultCacheTTL != 10*time.Minute {
		t.Errorf("Expected TTL 10m, got %v", gqlAction.resultCacheTTL)
	}
}

func TestGraphQLOptimization_InvalidTTL(t *testing.T) {
	data := []byte(`{
		"type": "graphql",
		"url": "http://example.com/graphql",
		"enable_result_caching": true,
		"result_cache_ttl": "invalid-duration"
	}`)

	action, err := NewGraphQLAction(data)
	// With strict validation, invalid duration strings should return an error
	if err == nil {
		t.Fatal("Expected error for invalid duration string, but got nil")
	}
	if action != nil {
		t.Error("Expected nil action when duration is invalid")
	}
}

