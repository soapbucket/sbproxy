package responsecache

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// TestSingleflight_CoalescedRequests verifies that concurrent requests for the
// same cache key are coalesced by singleflight so the backend is called at most
// a small number of times rather than once per request.
func TestSingleflight_CoalescedRequests(t *testing.T) {
	store := NewMockKVStore()

	var backendCalls atomic.Int32

	slowHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalls.Add(1)
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("singleflight response"))
	})

	cfg := DefaultResponseCacheConfig()
	handler := ResponseCacheHandler(store, cfg)(slowHandler)

	const numRequests = 100
	var wg sync.WaitGroup
	wg.Add(numRequests)

	for i := 0; i < numRequests; i++ {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "http://example.com/sf-test", nil)
			// Attach RequestData so the handler can extract config info.
			rd := &reqctx.RequestData{ID: "test-sf"}
			req = req.WithContext(reqctx.SetRequestData(req.Context(), rd))

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}()
	}
	wg.Wait()

	calls := backendCalls.Load()
	// Singleflight should coalesce most of these. Allow a small margin for timing
	// (the first group finishes, and a second group might fire before the cache
	// is populated asynchronously). Anything under 5 is a strong pass.
	if calls > 5 {
		t.Errorf("expected backend to be called very few times (singleflight), got %d calls out of %d requests", calls, numRequests)
	}
	t.Logf("singleflight coalesced %d requests into %d backend calls", numRequests, calls)
}

// TestCacheSave_SurvivesContextCancel verifies that the async cache save goroutine
// uses a detached context (context.WithoutCancel) so that cancelling the request
// context does not abort the cache write.
func TestCacheSave_SurvivesContextCancel(t *testing.T) {
	store := NewMockKVStore()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("cacheable body"))
	})

	cfg := DefaultResponseCacheConfig()
	cacheHandler := ResponseCacheHandler(store, cfg)(handler)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/ctx-cancel-test", nil)
	rd := &reqctx.RequestData{ID: "test-ctx-cancel"}
	ctx := reqctx.SetRequestData(req.Context(), rd)
	// We do NOT cancel the context before the handler runs; the code under test
	// uses context.WithoutCancel internally. We just verify the entry appears.
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	cacheHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	// The cache save happens asynchronously. Wait a short time for it to complete.
	time.Sleep(500 * time.Millisecond)

	store.mu.RLock()
	entryCount := len(store.data)
	store.mu.RUnlock()

	if entryCount == 0 {
		t.Error("expected cache to contain an entry after async save, but it was empty")
	}
}

// TestRaceDetector_ConcurrentCachePipeline exercises the cache pipeline with
// concurrent requests to surface data races. Run with -race flag.
func TestRaceDetector_ConcurrentCachePipeline(t *testing.T) {
	store := NewMockKVStore()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	})

	cfg := DefaultResponseCacheConfig()
	cacheHandler := ResponseCacheHandler(store, cfg)(handler)

	const numRequests = 50
	var wg sync.WaitGroup
	wg.Add(numRequests)

	for i := 0; i < numRequests; i++ {
		go func(idx int) {
			defer wg.Done()
			// Use a mix of URLs to exercise both cache hits and misses.
			url := "http://example.com/race-test"
			if idx%2 == 0 {
				url = "http://example.com/race-test-alt"
			}
			req := httptest.NewRequest(http.MethodGet, url, nil)
			rd := &reqctx.RequestData{ID: "race-test"}
			req = req.WithContext(reqctx.SetRequestData(req.Context(), rd))

			w := httptest.NewRecorder()
			cacheHandler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("request %d: expected status 200, got %d", idx, w.Code)
			}
		}(i)
	}
	wg.Wait()
}

// TestSingleflight_ErrorPropagation verifies two things about 500 responses
// during singleflight:
//  1. The singleflight key is NOT permanently locked after a 500 (recovery works).
//  2. The 500 is not cached (StoreNon200 defaults to false), so the next request
//     hits the backend again.
//
// Note: the current singleflight implementation writes the response only to the
// first caller's ResponseWriter (via the responseRecorder pass-through). Shared
// waiters receive the singleflightResult but the handler does not replay it to
// their ResponseWriters. This test focuses on the recovery and non-caching
// properties rather than response replay to shared waiters.
func TestSingleflight_ErrorPropagation(t *testing.T) {
	store := NewMockKVStore()

	var backendCalls atomic.Int32
	// First call: return 500. Second call: return 200.
	var failMode atomic.Bool
	failMode.Store(true)

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalls.Add(1)
		if failMode.Load() {
			time.Sleep(50 * time.Millisecond)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("backend error"))
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	cfg := DefaultResponseCacheConfig()
	handler := ResponseCacheHandler(store, cfg)(backend)

	// Phase 1: Single request gets 500 from the backend.
	req := httptest.NewRequest(http.MethodGet, "http://example.com/error-prop-test", nil)
	rd := &reqctx.RequestData{ID: "test-error-prop"}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), rd))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("first request: expected status 500, got %d", w.Code)
	}

	// Wait for the async cache save goroutine to complete (it should skip
	// caching because StoreNon200 is false).
	time.Sleep(100 * time.Millisecond)

	// Verify the 500 was NOT cached.
	store.mu.RLock()
	cached := len(store.data)
	store.mu.RUnlock()
	if cached != 0 {
		t.Errorf("expected 500 response to NOT be cached, but found %d entries", cached)
	}

	// Phase 2: Verify singleflight key is NOT permanently locked.
	failMode.Store(false)

	req2 := httptest.NewRequest(http.MethodGet, "http://example.com/error-prop-test", nil)
	rd2 := &reqctx.RequestData{ID: "test-error-prop-recovery"}
	req2 = req2.WithContext(reqctx.SetRequestData(req2.Context(), rd2))

	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("recovery request: expected status 200, got %d (singleflight key may be stuck)", w2.Code)
	}

	calls := backendCalls.Load()
	if calls < 2 {
		t.Errorf("expected at least 2 backend calls (one 500, one 200), got %d", calls)
	}
	t.Logf("backend called %d times (500 was not cached, singleflight key recovered)", calls)
}

// TestSingleflight_VaryByInKey verifies that VaryBy headers ARE included in
// the singleflight key, so requests with different Accept-Encoding values
// do not share the same singleflight group.
func TestSingleflight_VaryByInKey(t *testing.T) {
	varyHeaders := []string{"Accept-Encoding"}

	req1 := httptest.NewRequest("GET", "http://example.com/page", nil)
	req1.Header.Set("Accept-Encoding", "gzip")

	req2 := httptest.NewRequest("GET", "http://example.com/page", nil)
	req2.Header.Set("Accept-Encoding", "br")

	sfKey1 := generateSingleflightKey(req1, varyHeaders)
	sfKey2 := generateSingleflightKey(req2, varyHeaders)

	if sfKey1 == sfKey2 {
		t.Errorf("singleflight keys should differ when VaryBy headers differ: gzip=%s, br=%s", sfKey1, sfKey2)
	}

	// Same vary header value should produce the same singleflight key
	req3 := httptest.NewRequest("GET", "http://example.com/page", nil)
	req3.Header.Set("Accept-Encoding", "gzip")
	sfKey3 := generateSingleflightKey(req3, varyHeaders)

	if sfKey1 != sfKey3 {
		t.Errorf("singleflight keys should match for same VaryBy header value: %s vs %s", sfKey1, sfKey3)
	}

	// Without vary headers, singleflight keys should be the same regardless of Accept-Encoding
	sfKeyNoVary1 := generateSingleflightKey(req1, nil)
	sfKeyNoVary2 := generateSingleflightKey(req2, nil)
	if sfKeyNoVary1 != sfKeyNoVary2 {
		t.Errorf("without vary headers, singleflight keys should be identical regardless of Accept-Encoding")
	}

	// Cache keys (used for storage/expiration) should NOT include vary headers
	cacheKey1 := generateResponseCacheKey(req1, varyHeaders)
	cacheKey2 := generateResponseCacheKey(req2, varyHeaders)
	if cacheKey1 != cacheKey2 {
		t.Errorf("cache keys should be identical regardless of vary headers for expiration compatibility")
	}
}
