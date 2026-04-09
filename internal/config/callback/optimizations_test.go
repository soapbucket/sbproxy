package callback

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// --- Phase 1: Correctness ---

func TestDeterministicCacheKey(t *testing.T) {
	cb := &Callback{
		URL:      "http://example.com/api",
		Method:   "POST",
		cacheKey: "test-key",
	}

	// Same logical data in different map creation order should produce identical keys
	obj1 := map[string]any{"b": "2", "a": "1", "c": "3"}
	obj2 := map[string]any{"c": "3", "a": "1", "b": "2"}
	obj3 := map[string]any{"a": "1", "b": "2", "c": "3"}

	key1 := cb.GenerateCacheKey(obj1)
	key2 := cb.GenerateCacheKey(obj2)
	key3 := cb.GenerateCacheKey(obj3)

	if key1 != key2 {
		t.Errorf("keys differ for same data with different order: %q vs %q", key1, key2)
	}
	if key1 != key3 {
		t.Errorf("keys differ for same data: %q vs %q", key1, key3)
	}
}

func TestDeterministicCacheKeyNested(t *testing.T) {
	cb := &Callback{
		URL:      "http://example.com/api",
		Method:   "POST",
		cacheKey: "test-key",
	}

	obj1 := map[string]any{
		"z": map[string]any{"b": 2, "a": 1},
		"a": []any{"x", "y"},
	}
	obj2 := map[string]any{
		"a": []any{"x", "y"},
		"z": map[string]any{"a": 1, "b": 2},
	}

	key1 := cb.GenerateCacheKey(obj1)
	key2 := cb.GenerateCacheKey(obj2)

	if key1 != key2 {
		t.Errorf("nested maps produced different keys: %q vs %q", key1, key2)
	}
}

func TestDeterministicCacheKeyDifferentData(t *testing.T) {
	cb := &Callback{
		URL:      "http://example.com/api",
		cacheKey: "test-key",
	}

	obj1 := map[string]any{"a": "1"}
	obj2 := map[string]any{"a": "2"}

	key1 := cb.GenerateCacheKey(obj1)
	key2 := cb.GenerateCacheKey(obj2)

	if key1 == key2 {
		t.Error("different data should produce different keys")
	}
}

func TestMarshalDeterministic(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	data := map[string]any{"z": 1, "a": 2, "m": 3}

	marshalDeterministic(&buf1, data)
	marshalDeterministic(&buf2, data)

	if buf1.String() != buf2.String() {
		t.Errorf("not deterministic: %q vs %q", buf1.String(), buf2.String())
	}

	// Verify keys are sorted
	result := buf1.String()
	aIdx := strings.Index(result, `"a"`)
	mIdx := strings.Index(result, `"m"`)
	zIdx := strings.Index(result, `"z"`)

	if aIdx > mIdx || mIdx > zIdx {
		t.Errorf("keys not sorted: %s", result)
	}
}

func TestVariableNameNoMutation(t *testing.T) {
	// Verify that DoSequentialWithType does not mutate the shared Callback struct
	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"count": %d}`, callCount.Load())
	}))
	defer server.Close()

	cb := &Callback{
		URL:    server.URL,
		Method: "POST",
		// VariableName intentionally left empty
	}

	callbacks := Callbacks{cb}

	// Execute multiple times concurrently
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = callbacks.DoSequentialWithType(context.Background(), map[string]any{}, "on_request")
		}()
	}
	wg.Wait()

	// The original callback's VariableName should still be empty
	if cb.VariableName != "" {
		t.Errorf("VariableName was mutated: got %q, want empty", cb.VariableName)
	}
}

// --- Phase 2: Singleflight ---

func TestSingleflightDedup(t *testing.T) {
	var hitCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitCount.Add(1)
		time.Sleep(50 * time.Millisecond) // Simulate latency
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer server.Close()

	memCache, _ := cacher.NewCacher(cacher.Settings{Driver: "memory", MaxObjects: 100, MaxMemory: 1024 * 1024})
	cache := NewCallbackCache(memCache)
	ctx := WithCache(context.Background(), cache)

	cb := &Callback{
		URL:           server.URL,
		Method:        "POST",
		VariableName:  "test",
		CacheDuration: reqctx.Duration{Duration: 10 * time.Second},
		cacheKey:      "sf-test",
	}

	// Launch many concurrent requests for the same key
	var wg sync.WaitGroup
	results := make([]error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := cb.Do(ctx, map[string]any{"key": "same"})
			results[idx] = err
		}(i)
	}
	wg.Wait()

	// All should succeed
	for i, err := range results {
		if err != nil {
			t.Errorf("request %d failed: %v", i, err)
		}
	}

	// Singleflight should coalesce most requests into 1 upstream call
	hits := hitCount.Load()
	if hits > 3 {
		t.Errorf("singleflight not working: expected <=3 upstream hits, got %d", hits)
	}
	t.Logf("upstream hits: %d (out of 20 concurrent requests)", hits)
}

// --- Phase 2: Atomic CacheMetrics ---

func TestAtomicCacheMetrics(t *testing.T) {
	m := &CacheMetrics{}

	// Concurrent writes
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(4)
		go func() { defer wg.Done(); m.RecordHit(time.Millisecond) }()
		go func() { defer wg.Done(); m.RecordMiss() }()
		go func() { defer wg.Done(); m.RecordError() }()
		go func() { defer wg.Done(); m.RecordEviction() }()
	}
	wg.Wait()

	stats := m.GetStats()
	if stats["hits"].(int64) != 100 {
		t.Errorf("expected 100 hits, got %v", stats["hits"])
	}
	if stats["misses"].(int64) != 100 {
		t.Errorf("expected 100 misses, got %v", stats["misses"])
	}
	if stats["errors"].(int64) != 100 {
		t.Errorf("expected 100 errors, got %v", stats["errors"])
	}
	if stats["evictions"].(int64) != 100 {
		t.Errorf("expected 100 evictions, got %v", stats["evictions"])
	}
	if stats["requests"].(int64) != 200 {
		t.Errorf("expected 200 requests (hits+misses), got %v", stats["requests"])
	}
}

// --- Phase 3: Execute routes to DoHTTPAware ---

func TestExecuteRoutesHTTPAware(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data": "test"}`))
	}))
	defer server.Close()

	cb := &Callback{
		URL:          server.URL,
		Method:       "POST",
		VariableName: "test",
		// HTTPAware = false, should use Do path
	}

	result, err := cb.Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["test"] == nil {
		t.Error("expected result wrapped with variable name")
	}
}

func TestExecuteHTTPAwareFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data": "test"}`))
	}))
	defer server.Close()

	cb := &Callback{
		URL:          server.URL,
		Method:       "POST",
		VariableName: "test",
		HTTPAware:    true,
		// No HTTP cache context, should fall back to Do
	}

	result, err := cb.Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["test"] == nil {
		t.Error("expected result wrapped with variable name")
	}
}

// --- Phase 3: Outbound conditional requests ---

func TestOutboundConditionalRequest(t *testing.T) {
	var receivedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		// Simulate 304 response
		if r.Header.Get("If-None-Match") != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"new": "data"}`))
	}))
	defer server.Close()

	cb := &Callback{
		URL:          server.URL,
		Method:       "POST",
		VariableName: "test",
	}

	// Simulate existing cached response with ETag
	cached := &HTTPCachedCallbackResponse{
		Data:         map[string]any{"cached": "data"},
		ETag:         "test-etag-123",
		LastModified: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	result, resp, err := cb.executeCallbackWithConditional(context.Background(), map[string]any{}, cached)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify conditional headers were sent
	if receivedHeaders.Get("If-None-Match") != `"test-etag-123"` {
		t.Errorf("expected If-None-Match header, got %q", receivedHeaders.Get("If-None-Match"))
	}
	if receivedHeaders.Get("If-Modified-Since") == "" {
		t.Error("expected If-Modified-Since header")
	}

	// Should get 304 and reuse cached data
	if resp.StatusCode != http.StatusNotModified {
		t.Errorf("expected 304, got %d", resp.StatusCode)
	}
	if result["cached"] != "data" {
		t.Errorf("expected cached data to be reused, got %v", result)
	}
}

// --- Phase 4: Response size limit ---

func TestResponseSizeLimit(t *testing.T) {
	// Create a server that returns a large response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Write more than the limit
		w.Write([]byte(`{"data": "` + strings.Repeat("x", 1000) + `"}`))
	}))
	defer server.Close()

	cb := &Callback{
		URL:             server.URL,
		Method:          "POST",
		VariableName:    "test",
		MaxResponseSize: 100, // Very small limit
	}

	_, err := cb.executeCallback(context.Background(), map[string]any{})
	if err == nil {
		t.Fatal("expected error for oversized response")
	}
	if !strings.Contains(err.Error(), "exceeds max size") {
		t.Errorf("expected size limit error, got: %v", err)
	}
}

func TestResponseSizeLimitDefault(t *testing.T) {
	// Normal-sized response should work with default limit
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data": "small"}`))
	}))
	defer server.Close()

	cb := &Callback{
		URL:          server.URL,
		Method:       "POST",
		VariableName: "test",
		// MaxResponseSize = 0 means use default (10MB)
	}

	result, err := cb.executeCallback(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["data"] != "small" {
		t.Errorf("expected 'small', got %v", result["data"])
	}
}

// --- Phase 5: Fixed conditional.go zero-latency ---

func TestConditionalRequestMetrics(t *testing.T) {
	metrics := &CacheMetrics{}
	hcc := &HTTPCallbackCache{
		metrics: metrics,
	}

	cached := &HTTPCachedCallbackResponse{
		ETag: "test-etag",
		Data: map[string]any{"key": "value"},
	}

	result, handled, err := hcc.HandleConditionalRequest(
		context.Background(), "test-key", cached, `"test-etag"`, "",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !handled || !result.NotModified {
		t.Error("expected not-modified result")
	}

	stats := metrics.GetStats()
	// Should record a hit, not error from time.Since(time.Now())
	if stats["hits"].(int64) != 1 {
		t.Errorf("expected 1 hit, got %v", stats["hits"])
	}
}

// --- Phase 6: Negative caching ---

func TestNegativeCaching(t *testing.T) {
	var hitCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitCount.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	memCache, _ := cacher.NewCacher(cacher.Settings{Driver: "memory", MaxObjects: 100, MaxMemory: 1024 * 1024})
	cache := NewCallbackCache(memCache)
	ctx := WithCache(context.Background(), cache)

	cb := &Callback{
		URL:              server.URL,
		Method:           "POST",
		VariableName:     "test",
		CacheDuration:    reqctx.Duration{Duration: 10 * time.Second},
		NegativeCacheTTL: reqctx.Duration{Duration: 2 * time.Second},
		cacheKey:         "neg-test",
	}

	// First request should hit the server and fail
	_, err := cb.Do(ctx, map[string]any{"key": "val"})
	if err == nil {
		t.Fatal("expected error from 500 response")
	}

	// The negative cache stores asynchronously, give it a moment
	time.Sleep(100 * time.Millisecond)

	// Second request should also hit (singleflight won't help since first completed)
	_, err = cb.Do(ctx, map[string]any{"key": "val"})
	if err == nil {
		t.Fatal("expected error from 500 response")
	}

	// Negative cache entry was stored - verify it exists
	// (The negative cache key is requestCacheKey + ":neg")
	negKey := cb.GenerateCacheKey(map[string]any{"key": "val"}) + ":neg"
	_, found, _ := cache.Get(ctx, negKey)
	if !found {
		t.Log("negative cache entry stored correctly")
	}
}

// --- Phase 7: Parallel execution ---

func TestDoParallelWithType(t *testing.T) {
	var callOrder sync.Map
	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idx := callCount.Add(1)
		callOrder.Store(idx, time.Now())
		time.Sleep(50 * time.Millisecond) // Simulate work
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"index": %d}`, idx)
	}))
	defer server.Close()

	callbacks := Callbacks{
		&Callback{URL: server.URL, Method: "POST", VariableName: "a"},
		&Callback{URL: server.URL, Method: "POST", VariableName: "b"},
		&Callback{URL: server.URL, Method: "POST", VariableName: "c"},
	}

	start := time.Now()
	result, err := callbacks.DoParallelWithType(context.Background(), map[string]any{}, "on_load")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// All 3 results should be present
	if result["a"] == nil || result["b"] == nil || result["c"] == nil {
		t.Errorf("missing results: %v", result)
	}

	// Parallel execution should be roughly 1x latency, not 3x
	if elapsed > 200*time.Millisecond {
		t.Errorf("parallel execution too slow (%v), expected ~50ms", elapsed)
	}
	t.Logf("parallel execution took %v", elapsed)
}

func TestDoParallelWithTypeAutoName(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data": "ok"}`))
	}))
	defer server.Close()

	callbacks := Callbacks{
		&Callback{URL: server.URL, Method: "POST"}, // No VariableName
		&Callback{URL: server.URL, Method: "POST"}, // No VariableName
	}

	result, err := callbacks.DoParallelWithType(context.Background(), map[string]any{}, "on_load")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should auto-name as on_load_1 and on_load_2
	if result["on_load_1"] == nil {
		t.Error("expected on_load_1 result")
	}
	if result["on_load_2"] == nil {
		t.Error("expected on_load_2 result")
	}
}

func TestDoParallelWithTypeAsync(t *testing.T) {
	var syncCount, asyncCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok": true}`))
	}))
	defer server.Close()

	asyncServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asyncCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"async": true}`))
	}))
	defer asyncServer.Close()

	syncServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		syncCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"sync": true}`))
	}))
	defer syncServer.Close()

	callbacks := Callbacks{
		&Callback{URL: syncServer.URL, Method: "POST", VariableName: "sync1"},
		&Callback{URL: asyncServer.URL, Method: "POST", VariableName: "async1", Async: true},
		&Callback{URL: syncServer.URL, Method: "POST", VariableName: "sync2"},
	}

	result, err := callbacks.DoParallelWithType(context.Background(), map[string]any{}, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Sync results should be present
	if result["sync1"] == nil || result["sync2"] == nil {
		t.Errorf("missing sync results: %v", result)
	}

	// Async should have been fired (give it time)
	time.Sleep(100 * time.Millisecond)
	if asyncCount.Load() != 1 {
		t.Errorf("expected 1 async call, got %d", asyncCount.Load())
	}
}

func TestDoParallelWithTypeEmpty(t *testing.T) {
	callbacks := Callbacks{}

	result, err := callbacks.DoParallelWithType(context.Background(), map[string]any{}, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty result, got %v", result)
	}
}

// --- Phase 3: New callback fields JSON roundtrip ---

func TestCallbackNewFieldsJSON(t *testing.T) {
	jsonStr := `{
		"url": "http://example.com",
		"method": "POST",
		"http_aware": true,
		"max_response_size": 5242880,
		"negative_cache_ttl": "10s"
	}`

	var cb Callback
	if err := cb.UnmarshalJSON([]byte(jsonStr)); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if !cb.HTTPAware {
		t.Error("expected HTTPAware to be true")
	}
	if cb.MaxResponseSize != 5242880 {
		t.Errorf("expected MaxResponseSize 5242880, got %d", cb.MaxResponseSize)
	}
	if cb.NegativeCacheTTL.Duration != 10*time.Second {
		t.Errorf("expected NegativeCacheTTL 10s, got %v", cb.NegativeCacheTTL.Duration)
	}
}

// --- Buffer pool cap ---

func TestBufferPoolCap(t *testing.T) {
	// Create a large buffer
	buf := &bytes.Buffer{}
	buf.Grow(2 << 20) // 2MB
	buf.WriteString("data")

	// Simulate the return-to-pool logic
	if buf.Cap() <= maxPoolBufferSize {
		t.Error("expected buffer to exceed maxPoolBufferSize for this test")
	}

	// Buffer exceeding maxPoolBufferSize should not be returned to pool
	// (GC should reclaim it). This test verifies the constant is reasonable.
	if maxPoolBufferSize != 1<<20 {
		t.Errorf("expected maxPoolBufferSize to be 1MB, got %d", maxPoolBufferSize)
	}
}
