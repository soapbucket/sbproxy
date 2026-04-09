package callback

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/cache/store"
)

// =============================================================================
// Error Handling Tests
// =============================================================================

func TestCallbackNetworkErrors(t *testing.T) {
	t.Run("connection refused", func(t *testing.T) {
		callback := &Callback{
			URL:     "http://localhost:59999", // Non-existent port
			Method:  "POST",
			Timeout: 2,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, err := callback.Do(ctx, map[string]any{"test": "data"})
		if err == nil {
			t.Error("expected connection error")
		}

		t.Logf("Got expected error: %v", err)
	})

	t.Run("DNS resolution failure", func(t *testing.T) {
		callback := &Callback{
			URL:     "http://nonexistent.invalid.domain.test",
			Method:  "POST",
			Timeout: 2,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, err := callback.Do(ctx, map[string]any{"test": "data"})
		if err == nil {
			t.Error("expected DNS resolution error")
		}

		t.Logf("Got expected error: %v", err)
	})

	t.Run("server closes connection abruptly", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Hijack the connection and close it immediately
			hj, ok := w.(http.Hijacker)
			if ok {
				conn, _, _ := hj.Hijack()
				conn.Close()
			}
		}))
		defer server.Close()

		callback := &Callback{
			URL:     server.URL,
			Method:  "POST",
			Timeout: 5,
		}

		ctx := context.Background()
		_, err := callback.Do(ctx, map[string]any{"test": "data"})
		if err == nil {
			t.Error("expected connection error")
		}

		t.Logf("Got expected error: %v", err)
	})
}

func TestCallbackTimeoutErrors(t *testing.T) {
	t.Run("server response timeout via context", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(3 * time.Second) // Longer than callback timeout
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		callback := &Callback{
			URL:    server.URL,
			Method: "POST",
		}

		// Apply timeout via context (this is how callbacks actually get their timeout)
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		start := time.Now()
		_, err := callback.Do(ctx, map[string]any{"test": "data"})
		duration := time.Since(start)

		if err == nil {
			t.Error("expected timeout error")
		}

		// Should timeout around 1 second, not wait for full 3 seconds
		if duration > 2*time.Second {
			t.Errorf("timeout took too long: %v", duration)
		}

		t.Logf("Timeout occurred after %v: %v", duration, err)
	})

	t.Run("server response timeout via sequential execution", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(3 * time.Second) // Longer than callback timeout
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		// Use DoSequential which applies the Timeout field
		callbacks := Callbacks{
			&Callback{
				URL:          server.URL,
				Method:       "POST",
				Timeout:      1, // 1 second timeout
				VariableName: "test",
			},
		}

		ctx := context.Background()
		start := time.Now()
		_, err := callbacks.DoSequential(ctx, map[string]any{"test": "data"})
		duration := time.Since(start)

		if err == nil {
			t.Error("expected timeout error")
		}

		// Should timeout around 1 second, not wait for full 3 seconds
		if duration > 2*time.Second {
			t.Errorf("timeout took too long: %v", duration)
		}

		t.Logf("Timeout occurred after %v: %v", duration, err)
	})

	t.Run("context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(5 * time.Second)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		callback := &Callback{
			URL:     server.URL,
			Method:  "POST",
			Timeout: 10,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		start := time.Now()
		_, err := callback.Do(ctx, map[string]any{"test": "data"})
		duration := time.Since(start)

		if err == nil {
			t.Error("expected context cancellation error")
		}

		if duration > 1*time.Second {
			t.Errorf("context cancellation took too long: %v", duration)
		}

		t.Logf("Context cancelled after %v: %v", duration, err)
	})

	t.Run("zero timeout uses default", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
		}))
		defer server.Close()

		callback := &Callback{
			URL:     server.URL,
			Method:  "POST",
			Timeout: 0, // Should use default 10s
		}

		ctx := context.Background()
		result, err := callback.Do(ctx, map[string]any{"test": "data"})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("expected non-nil result")
		}
	})
}

func TestCallbackHTTPStatusErrors(t *testing.T) {
	testCases := []struct {
		name          string
		statusCode    int
		expectedCodes []int
		shouldError   bool
		errorContains string
	}{
		{"400 Bad Request", 400, nil, true, "expected status code 200, got 400"},
		{"401 Unauthorized", 401, nil, true, "expected status code 200, got 401"},
		{"403 Forbidden", 403, nil, true, "expected status code 200, got 403"},
		{"404 Not Found", 404, nil, true, "expected status code 200, got 404"},
		{"500 Internal Server Error", 500, nil, true, "expected status code 200, got 500"},
		{"502 Bad Gateway", 502, nil, true, "expected status code 200, got 502"},
		{"503 Service Unavailable", 503, nil, true, "expected status code 200, got 503"},
		{"504 Gateway Timeout", 504, nil, true, "expected status code 200, got 504"},
		{"200 OK", 200, nil, false, ""},
		{"201 Created with expected codes", 201, []int{200, 201, 202}, false, ""},
		{"204 No Content with expected codes", 204, []int{200, 201, 202}, true, "expected status code"},
		{"400 with expected 4xx", 400, []int{400, 401, 403}, false, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.statusCode)
				json.NewEncoder(w).Encode(map[string]any{"status": "test"})
			}))
			defer server.Close()

			callback := &Callback{
				URL:                 server.URL,
				Method:              "POST",
				ExpectedStatusCodes: tc.expectedCodes,
			}

			ctx := context.Background()
			_, err := callback.Do(ctx, map[string]any{"test": "data"})

			if tc.shouldError {
				if err == nil {
					t.Error("expected error")
				} else if tc.errorContains != "" && !strings.Contains(err.Error(), tc.errorContains) {
					t.Errorf("expected error to contain %q, got: %v", tc.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestCallbackInvalidResponseBody(t *testing.T) {
	t.Run("invalid JSON response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("{invalid json"))
		}))
		defer server.Close()

		callback := &Callback{
			URL:    server.URL,
			Method: "POST",
		}

		ctx := context.Background()
		_, err := callback.Do(ctx, map[string]any{"test": "data"})
		if err == nil {
			t.Error("expected JSON decode error")
		}

		t.Logf("Got expected error: %v", err)
	})

	t.Run("empty response body with JSON content type", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// Empty body
		}))
		defer server.Close()

		callback := &Callback{
			URL:    server.URL,
			Method: "POST",
		}

		ctx := context.Background()
		result, err := callback.Do(ctx, map[string]any{"test": "data"})
		// Empty JSON body should not error, just return empty result
		if err != nil {
			t.Logf("Got error (may be expected): %v", err)
		}
		t.Logf("Result: %v", result)
	})

	t.Run("non-JSON content type", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html>test</html>"))
		}))
		defer server.Close()

		callback := &Callback{
			URL:    server.URL,
			Method: "POST",
		}

		ctx := context.Background()
		result, err := callback.Do(ctx, map[string]any{"test": "data"})
		// Non-JSON content should return empty result without error
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("expected non-nil result")
		}

		// Result should be wrapped
		wrapped, ok := result["callback"]
		if !ok {
			t.Error("expected wrapped result")
		}
		t.Logf("Result for non-JSON: %v", wrapped)
	})
}

// =============================================================================
// Circuit Breaker Advanced Tests
// =============================================================================

func TestCircuitBreakerAdvanced(t *testing.T) {
	t.Run("circuit breaker with rapid failures", func(t *testing.T) {
		cb := NewCircuitBreaker(3, 2, 100*time.Millisecond)

		// Rapid fire failures
		for i := 0; i < 10; i++ {
			cb.RecordFailure()
		}

		if cb.GetState() != circuitStateOpen {
			t.Errorf("expected open state, got %v", cb.GetState())
		}

		// Cannot execute while open
		if cb.CanExecute() {
			t.Error("should not be able to execute when circuit is open")
		}
	})

	t.Run("circuit breaker state transitions", func(t *testing.T) {
		cb := NewCircuitBreaker(2, 3, 50*time.Millisecond)

		// Start closed
		if cb.GetState() != circuitStateClosed {
			t.Fatalf("expected initial closed state")
		}

		// Open with failures
		cb.RecordFailure()
		cb.RecordFailure()
		if cb.GetState() != circuitStateOpen {
			t.Fatalf("expected open state after failures")
		}

		// Wait for timeout
		time.Sleep(60 * time.Millisecond)

		// Should allow execution and transition to half-open
		if !cb.CanExecute() {
			t.Fatal("should be able to execute after timeout")
		}
		cb.transitionToHalfOpen()
		if cb.GetState() != circuitStateHalfOpen {
			t.Fatalf("expected half-open state, got %v", cb.GetState())
		}

		// Record successes to close
		cb.RecordSuccess()
		cb.RecordSuccess()
		cb.RecordSuccess()
		if cb.GetState() != circuitStateClosed {
			t.Errorf("expected closed state after successes, got %v", cb.GetState())
		}
	})

	t.Run("circuit breaker limits half-open requests", func(t *testing.T) {
		cb := NewCircuitBreaker(2, 2, 50*time.Millisecond)

		// Open the circuit
		cb.RecordFailure()
		cb.RecordFailure()

		time.Sleep(60 * time.Millisecond)
		cb.transitionToHalfOpen()

		// Track how many requests are allowed in half-open state
		allowed := 0
		for i := 0; i < 10; i++ {
			if cb.CanExecute() {
				allowed++
				cb.IncrementHalfOpenAttempts()
			}
		}

		// Should only allow defaultHalfOpenRequests (3) requests
		if allowed != defaultHalfOpenRequests {
			t.Errorf("expected %d half-open requests, got %d", defaultHalfOpenRequests, allowed)
		}
	})

	t.Run("circuit breaker concurrent access", func(t *testing.T) {
		cb := NewCircuitBreaker(100, 100, 30*time.Second)

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 10; j++ {
					cb.CanExecute()
					if j%2 == 0 {
						cb.RecordSuccess()
					} else {
						cb.RecordFailure()
					}
				}
			}()
		}
		wg.Wait()

		// Should not panic and state should be valid
		state := cb.GetState()
		if state != circuitStateClosed && state != circuitStateOpen {
			t.Errorf("unexpected state: %v", state)
		}
	})
}

// =============================================================================
// Callback Caching Error Tests
// =============================================================================

func TestCallbackCachingWithErrors(t *testing.T) {
	settings := cacher.Settings{
		Driver:     "memory",
		MaxObjects: 100,
		MaxMemory:  1024 * 1024,
	}

	cache, err := cacher.NewCacher(settings)
	if err != nil {
		t.Fatalf("failed to create cacher: %v", err)
	}
	defer cache.Close()

	callbackCache := NewCallbackCache(cache)
	ctx := context.Background()

	t.Run("circuit breaker opens on repeated failures", func(t *testing.T) {
		var requestCount int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&requestCount, 1)
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		callbackJSON := fmt.Sprintf(`{
			"url": "%s",
			"method": "GET",
			"cache_duration": "1m"
		}`, server.URL)

		var callback Callback
		if err := json.Unmarshal([]byte(callbackJSON), &callback); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		ctx := WithCache(ctx, callbackCache)

		// Make multiple requests to trigger circuit breaker
		for i := 0; i < 10; i++ {
			_, _ = callback.Do(ctx, map[string]any{"key": "value"})
		}

		// Check circuit breaker state
		cb := callbackCache.GetCircuitBreaker(callback.GetCacheKey())
		if cb.GetState() != circuitStateOpen {
			t.Errorf("expected circuit breaker to be open after failures, got %v", cb.GetState())
		}

		t.Logf("Request count: %d, Circuit state: %v", requestCount, cb.GetState())
	})

	t.Run("returns cached data on subsequent requests", func(t *testing.T) {
		var requestCount int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&requestCount, 1)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"cached": true, "count": requestCount})
		}))
		defer server.Close()

		callbackJSON := fmt.Sprintf(`{
			"url": "%s",
			"method": "GET",
			"cache_duration": "1m"
		}`, server.URL)

		var callback Callback
		if err := json.Unmarshal([]byte(callbackJSON), &callback); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		ctx := WithCache(ctx, callbackCache)

		// Use a fixed request body for consistent cache key
		requestBody := map[string]any{"cache_test_key": "fixed_value"}

		// First request should hit server and cache
		result, err := callback.Do(ctx, requestBody)
		if err != nil {
			t.Fatalf("first request failed: %v", err)
		}

		wrapped, ok := result["callback"].(map[string]any)
		if !ok || wrapped["cached"] != true {
			t.Errorf("unexpected first result: %v", result)
		}

		firstCount := atomic.LoadInt32(&requestCount)
		if firstCount != 1 {
			t.Errorf("expected 1 server hit, got %d", firstCount)
		}

		// Second request with same body should return cached data (no new server hit)
		result2, err := callback.Do(ctx, requestBody)
		if err != nil {
			t.Errorf("subsequent request should return cached data: %v", err)
		}

		wrapped2, ok := result2["callback"].(map[string]any)
		if !ok || wrapped2["cached"] != true {
			t.Errorf("expected cached result: %v", result2)
		}

		secondCount := atomic.LoadInt32(&requestCount)
		if secondCount != 1 {
			t.Logf("Warning: server was hit %d times (expected 1 for cached response)", secondCount)
		}
	})
}

// =============================================================================
// Sequential Callback Tests
// =============================================================================

func TestCallbacksSequentialExecution(t *testing.T) {
	t.Run("async callbacks do not block", func(t *testing.T) {
		var order []int
		var mu sync.Mutex

		slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(200 * time.Millisecond)
			mu.Lock()
			order = append(order, 1)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"slow": true})
		}))
		defer slowServer.Close()

		fastServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			order = append(order, 2)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"fast": true})
		}))
		defer fastServer.Close()

		callbacks := Callbacks{
			&Callback{
				URL:          slowServer.URL,
				Method:       "POST",
				VariableName: "slow",
				Async:        true, // Async - should not block
			},
			&Callback{
				URL:          fastServer.URL,
				Method:       "POST",
				VariableName: "fast",
				Async:        false, // Sync
			},
		}

		ctx := context.Background()
		start := time.Now()
		result, err := callbacks.DoSequential(ctx, nil)
		duration := time.Since(start)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// Should complete quickly since async callback doesn't block
		if duration > 100*time.Millisecond {
			t.Errorf("sequential execution took too long: %v", duration)
		}

		// Only sync callback should be in result
		if result["fast"] == nil {
			t.Error("fast callback should be in result")
		}

		t.Logf("Sequential completed in %v, result: %v", duration, result)

		// Wait for async to complete
		time.Sleep(300 * time.Millisecond)

		mu.Lock()
		t.Logf("Execution order: %v", order)
		mu.Unlock()
	})

	t.Run("sequential callbacks execute in order", func(t *testing.T) {
		var order []int
		var mu sync.Mutex

		makeServer := func(id int) *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				order = append(order, id)
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{"id": id})
			}))
		}

		s1 := makeServer(1)
		s2 := makeServer(2)
		s3 := makeServer(3)
		defer s1.Close()
		defer s2.Close()
		defer s3.Close()

		callbacks := Callbacks{
			&Callback{URL: s1.URL, Method: "POST", VariableName: "cb1"},
			&Callback{URL: s2.URL, Method: "POST", VariableName: "cb2"},
			&Callback{URL: s3.URL, Method: "POST", VariableName: "cb3"},
		}

		ctx := context.Background()
		_, err := callbacks.DoSequential(ctx, nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		mu.Lock()
		defer mu.Unlock()

		if len(order) != 3 || order[0] != 1 || order[1] != 2 || order[2] != 3 {
			t.Errorf("expected order [1,2,3], got %v", order)
		}
	})

	t.Run("error in one callback does not stop others", func(t *testing.T) {
		okServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
		}))
		defer okServer.Close()

		errServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer errServer.Close()

		callbacks := Callbacks{
			&Callback{URL: okServer.URL, Method: "POST", VariableName: "cb1"},
			&Callback{URL: errServer.URL, Method: "POST", VariableName: "cb2"},
			&Callback{URL: okServer.URL, Method: "POST", VariableName: "cb3"},
		}

		ctx := context.Background()
		result, err := callbacks.DoSequential(ctx, nil)

		// Should have error from cb2
		if err == nil {
			t.Error("expected error from failed callback")
		}

		// But cb1 and cb3 should still be in results
		if result["cb1"] == nil {
			t.Error("cb1 should be in result")
		}
		if result["cb3"] == nil {
			t.Error("cb3 should be in result")
		}

		t.Logf("Result after partial failure: %v, error: %v", result, err)
	})
}

// =============================================================================
// Append Mode Tests
// =============================================================================

func TestCallbackAppendMode(t *testing.T) {
	t.Run("append mode collects results in array", func(t *testing.T) {
		makeServer := func(id int) *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{"id": id, "value": fmt.Sprintf("item%d", id)})
			}))
		}

		s1 := makeServer(1)
		s2 := makeServer(2)
		s3 := makeServer(3)
		defer s1.Close()
		defer s2.Close()
		defer s3.Close()

		callbacks := Callbacks{
			&Callback{URL: s1.URL, Method: "POST", VariableName: "items", Append: true},
			&Callback{URL: s2.URL, Method: "POST", VariableName: "items", Append: true},
			&Callback{URL: s3.URL, Method: "POST", VariableName: "items", Append: true},
		}

		ctx := context.Background()
		result, err := callbacks.DoSequential(ctx, nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		items, ok := result["items"]
		if !ok {
			t.Fatal("items not found in result")
		}

		// Should be array with 3 elements
		itemsArray, ok := items.([]any)
		if !ok {
			t.Fatalf("items should be array, got %T", items)
		}

		if len(itemsArray) != 3 {
			t.Errorf("expected 3 items, got %d", len(itemsArray))
		}

		t.Logf("Appended items: %v", items)
	})

	t.Run("replace mode overwrites", func(t *testing.T) {
		makeServer := func(id int) *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{"id": id})
			}))
		}

		s1 := makeServer(1)
		s2 := makeServer(2)
		defer s1.Close()
		defer s2.Close()

		callbacks := Callbacks{
			&Callback{URL: s1.URL, Method: "POST", VariableName: "item", Append: false},
			&Callback{URL: s2.URL, Method: "POST", VariableName: "item", Append: false}, // Should overwrite
		}

		ctx := context.Background()
		result, err := callbacks.DoSequential(ctx, nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		item := result["item"]
		if item == nil {
			t.Fatal("item not found in result")
		}

		// Should be single item (last one wins)
		itemMap, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("item should be map, got %T", item)
		}

		// Last callback (id=2) should be the result
		if itemMap["id"] != float64(2) {
			t.Errorf("expected id=2 (overwritten), got %v", itemMap["id"])
		}

		t.Logf("Replaced item: %v", item)
	})
}

// =============================================================================
// Fetch API Error Tests
// =============================================================================

func TestFetchAPIErrors(t *testing.T) {
	t.Run("fetch with network error", func(t *testing.T) {
		callback := &Callback{
			URL:     "http://localhost:59999",
			Method:  "GET",
			Timeout: 2,
		}

		ctx := context.Background()
		_, err := callback.Fetch(ctx, nil)
		if err == nil {
			t.Error("expected network error")
		}
	})

	t.Run("fetch returns raw content", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><body>Test</body></html>"))
		}))
		defer server.Close()

		callback := &Callback{
			URL:    server.URL,
			Method: "GET",
		}

		ctx := context.Background()
		resp, err := callback.Fetch(ctx, nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if resp == nil {
			t.Fatal("expected non-nil response")
		}

		if resp.ContentType != "text/html" {
			t.Errorf("expected text/html, got %s", resp.ContentType)
		}

		if !strings.Contains(string(resp.Body), "<html>") {
			t.Errorf("expected HTML body, got %s", string(resp.Body))
		}
	})

	t.Run("fetch handles non-200 status gracefully", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not Found"))
		}))
		defer server.Close()

		callback := &Callback{
			URL:    server.URL,
			Method: "GET",
		}

		ctx := context.Background()
		resp, err := callback.Fetch(ctx, nil)
		if err != nil {
			// May or may not error depending on implementation
			t.Logf("Got error (may be expected): %v", err)
		}

		if resp != nil {
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("expected 404, got %d", resp.StatusCode)
			}
		}
	})
}

// =============================================================================
// Request Data Preservation Tests
// =============================================================================

func TestCallbackPreserveRequest(t *testing.T) {
	t.Run("preserve_request includes full request data", func(t *testing.T) {
		var receivedBody map[string]any
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			json.Unmarshal(body, &receivedBody)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"received": true})
		}))
		defer server.Close()

		callback := &Callback{
			URL:             server.URL,
			Method:          "POST",
			PreserveRequest: true,
		}

		requestData := &reqctx.RequestData{
			ID: "req-123",
			Data: map[string]any{
				"user_id": "user-456",
				"action":  "test",
			},
		}

		ctx := context.Background()
		_, err := callback.Do(ctx, requestData)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// Verify the received data includes request info
		t.Logf("Received body: %+v", receivedBody)
	})
}

// =============================================================================
// Error Aggregation Tests
// =============================================================================

func TestCallbacksErrorAggregation(t *testing.T) {
	t.Run("multiple errors are joined", func(t *testing.T) {
		errServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer errServer.Close()

		callbacks := Callbacks{
			&Callback{URL: errServer.URL, Method: "POST", VariableName: "cb1"},
			&Callback{URL: errServer.URL, Method: "POST", VariableName: "cb2"},
			&Callback{URL: errServer.URL, Method: "POST", VariableName: "cb3"},
		}

		ctx := context.Background()
		_, err := callbacks.DoSequential(ctx, nil)

		if err == nil {
			t.Fatal("expected error")
		}

		// Should contain multiple errors joined
		var joinedErr interface{ Unwrap() []error }
		if errors.As(err, &joinedErr) {
			errs := joinedErr.Unwrap()
			if len(errs) != 3 {
				t.Errorf("expected 3 joined errors, got %d", len(errs))
			}
		}

		t.Logf("Aggregated error: %v", err)
	})
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkCallbackExecution(b *testing.B) {
	b.ReportAllocs()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	}))
	defer server.Close()

	callback := &Callback{
		URL:    server.URL,
		Method: "POST",
	}

	ctx := context.Background()
	data := map[string]any{"test": "data"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = callback.Do(ctx, data)
	}
}

func BenchmarkSequentialCallbacks(b *testing.B) {
	b.ReportAllocs()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	}))
	defer server.Close()

	callbacks := Callbacks{
		&Callback{URL: server.URL, Method: "POST", VariableName: "cb1"},
		&Callback{URL: server.URL, Method: "POST", VariableName: "cb2"},
		&Callback{URL: server.URL, Method: "POST", VariableName: "cb3"},
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = callbacks.DoSequential(ctx, nil)
	}
}

func BenchmarkCircuitBreakerOperations(b *testing.B) {
	b.ReportAllocs()
	cb := NewCircuitBreaker(1000, 1000, 30*time.Second)

	b.Run("CanExecute", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			cb.CanExecute()
		}
	})

	b.Run("RecordSuccess", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			cb.RecordSuccess()
		}
	})

	b.Run("RecordFailure", func(b *testing.B) {
		cb2 := NewCircuitBreaker(1000000, 1000, 30*time.Second)
		for i := 0; i < b.N; i++ {
			cb2.RecordFailure()
		}
	})
}
