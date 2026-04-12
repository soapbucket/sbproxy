package responsecache

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	cacher "github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func newTestCache(t *testing.T) cacher.Cacher {
	t.Helper()
	cache, err := cacher.NewCacher(cacher.Settings{
		Driver: "memory",
		Params: map[string]string{"max_size": "10485760"},
	})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}
	return cache
}

func newTestRequest(t *testing.T, method, path, id string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, "http://test.local"+path, nil)
	rd := reqctx.NewRequestData()
	rd.ID = id
	req = req.WithContext(reqctx.SetRequestData(req.Context(), rd))
	return req
}

// --- Response Cache X-Cache Tests ---

func TestXCacheHeader_MissOnFirstRequest(t *testing.T) {
	t.Parallel()
	cache := newTestCache(t)

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"data":"hello"}`))
	})

	config := DefaultResponseCacheConfig()
	handler := ResponseCacheHandler(cache, config)(backend)

	req := newTestRequest(t, "GET", "/api/data", "test-miss")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	xcache := rr.Header().Get("X-Cache")
	if xcache != "MISS" {
		t.Errorf("expected X-Cache: MISS on first request, got %q", xcache)
	}
}

func TestXCacheHeader_HitOnSecondRequest(t *testing.T) {
	t.Parallel()
	cache := newTestCache(t)

	callCount := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"data":"hello"}`))
	})

	config := DefaultResponseCacheConfig()
	handler := ResponseCacheHandler(cache, config)(backend)

	// First request - MISS
	req1 := newTestRequest(t, "GET", "/api/data", "test-hit-1")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	if rr1.Header().Get("X-Cache") != "MISS" {
		t.Errorf("first request: expected X-Cache: MISS, got %q", rr1.Header().Get("X-Cache"))
	}

	// Wait for async cache save to complete
	time.Sleep(100 * time.Millisecond)

	// Second request - HIT
	req2 := newTestRequest(t, "GET", "/api/data", "test-hit-2")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	xcache := rr2.Header().Get("X-Cache")
	if xcache != "HIT" {
		t.Errorf("second request: expected X-Cache: HIT, got %q", xcache)
	}

	if callCount != 1 {
		t.Errorf("expected backend called once, got %d", callCount)
	}
}

func TestXCacheHeader_PostRequestNotCached(t *testing.T) {
	t.Parallel()
	cache := newTestCache(t)

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"data":"post"}`))
	})

	config := DefaultResponseCacheConfig()
	handler := ResponseCacheHandler(cache, config)(backend)

	req := newTestRequest(t, "POST", "/api/data", "test-post")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// POST requests bypass cache entirely - no X-Cache header
	xcache := rr.Header().Get("X-Cache")
	if xcache != "" {
		t.Errorf("POST request should not have X-Cache header, got %q", xcache)
	}
}

func TestXCacheHeader_NoStoreAlwaysMiss(t *testing.T) {
	t.Parallel()
	cache := newTestCache(t)

	callCount := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(200)
		w.Write([]byte(fmt.Sprintf(`{"count":%d}`, callCount)))
	})

	config := DefaultResponseCacheConfig()
	handler := ResponseCacheHandler(cache, config)(backend)

	// First request - MISS
	req1 := newTestRequest(t, "GET", "/api/no-store", "test-nostore-1")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	if rr1.Header().Get("X-Cache") != "MISS" {
		t.Errorf("first request: expected X-Cache: MISS, got %q", rr1.Header().Get("X-Cache"))
	}

	time.Sleep(100 * time.Millisecond)

	// Second request - still MISS (no-store means never cached)
	req2 := newTestRequest(t, "GET", "/api/no-store", "test-nostore-2")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	xcache := rr2.Header().Get("X-Cache")
	if xcache != "MISS" {
		t.Errorf("no-store second request: expected X-Cache: MISS, got %q", xcache)
	}

	// Backend should have been called twice (not cached)
	if callCount != 2 {
		t.Errorf("no-store: expected backend called twice, got %d", callCount)
	}
}

func TestXCacheHeader_NoCacheAlwaysMiss(t *testing.T) {
	t.Parallel()
	cache := newTestCache(t)

	callCount := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(200)
		w.Write([]byte(fmt.Sprintf(`{"count":%d}`, callCount)))
	})

	config := DefaultResponseCacheConfig()
	handler := ResponseCacheHandler(cache, config)(backend)

	req1 := newTestRequest(t, "GET", "/api/no-cache", "test-nocache-1")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	time.Sleep(100 * time.Millisecond)

	req2 := newTestRequest(t, "GET", "/api/no-cache", "test-nocache-2")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	xcache := rr2.Header().Get("X-Cache")
	if xcache != "MISS" {
		t.Errorf("no-cache second request: expected X-Cache: MISS, got %q", xcache)
	}

	if callCount != 2 {
		t.Errorf("no-cache: expected backend called twice, got %d", callCount)
	}
}

func TestXCacheHeader_PrivateNotCachedByDefault(t *testing.T) {
	t.Parallel()
	cache := newTestCache(t)

	callCount := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private, max-age=300")
		w.WriteHeader(200)
		w.Write([]byte(fmt.Sprintf(`{"count":%d}`, callCount)))
	})

	config := DefaultResponseCacheConfig()
	handler := ResponseCacheHandler(cache, config)(backend)

	req1 := newTestRequest(t, "GET", "/api/private", "test-private-1")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	time.Sleep(100 * time.Millisecond)

	req2 := newTestRequest(t, "GET", "/api/private", "test-private-2")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	xcache := rr2.Header().Get("X-Cache")
	if xcache != "MISS" {
		t.Errorf("private second request: expected X-Cache: MISS, got %q", xcache)
	}

	if callCount != 2 {
		t.Errorf("private: expected backend called twice, got %d", callCount)
	}
}

func TestXCacheHeader_MaxAgeRespected(t *testing.T) {
	t.Parallel()
	cache := newTestCache(t)

	callCount := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.WriteHeader(200)
		w.Write([]byte(fmt.Sprintf(`{"count":%d}`, callCount)))
	})

	config := DefaultResponseCacheConfig()
	handler := ResponseCacheHandler(cache, config)(backend)

	// First request - MISS
	req1 := newTestRequest(t, "GET", "/api/maxage", "test-maxage-1")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	if rr1.Header().Get("X-Cache") != "MISS" {
		t.Errorf("first request: expected MISS, got %q", rr1.Header().Get("X-Cache"))
	}

	time.Sleep(100 * time.Millisecond)

	// Second request - HIT (within max-age)
	req2 := newTestRequest(t, "GET", "/api/maxage", "test-maxage-2")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Header().Get("X-Cache") != "HIT" {
		t.Errorf("second request within max-age: expected HIT, got %q", rr2.Header().Get("X-Cache"))
	}

	if callCount != 1 {
		t.Errorf("expected backend called once, got %d", callCount)
	}

	// Verify cached body matches original
	if rr2.Body.String() != `{"count":1}` {
		t.Errorf("cached body mismatch: got %q", rr2.Body.String())
	}
}

func TestXCacheHeader_HeadRequestCacheable(t *testing.T) {
	t.Parallel()
	cache := newTestCache(t)

	callCount := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.WriteHeader(200)
		if r.Method != http.MethodHead {
			w.Write([]byte(`{"data":"head-test"}`))
		}
	})

	config := DefaultResponseCacheConfig()
	handler := ResponseCacheHandler(cache, config)(backend)

	// HEAD request should also get X-Cache header
	req := newTestRequest(t, "HEAD", "/api/head", "test-head")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	xcache := rr.Header().Get("X-Cache")
	if xcache != "MISS" {
		t.Errorf("HEAD first request: expected MISS, got %q", xcache)
	}
}

func TestXCacheHeader_DifferentPathsDifferentCacheEntries(t *testing.T) {
	t.Parallel()
	cache := newTestCache(t)

	callCount := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(fmt.Sprintf(`{"path":"%s","count":%d}`, r.URL.Path, callCount)))
	})

	config := DefaultResponseCacheConfig()
	handler := ResponseCacheHandler(cache, config)(backend)

	// Request path A
	req1 := newTestRequest(t, "GET", "/api/a", "test-path-a")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	time.Sleep(100 * time.Millisecond)

	// Request path B - should be MISS (different cache key)
	req2 := newTestRequest(t, "GET", "/api/b", "test-path-b")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Header().Get("X-Cache") != "MISS" {
		t.Errorf("different path should be MISS, got %q", rr2.Header().Get("X-Cache"))
	}

	// Request path A again - should be HIT
	req3 := newTestRequest(t, "GET", "/api/a", "test-path-a2")
	rr3 := httptest.NewRecorder()
	handler.ServeHTTP(rr3, req3)

	if rr3.Header().Get("X-Cache") != "HIT" {
		t.Errorf("same path again should be HIT, got %q", rr3.Header().Get("X-Cache"))
	}

	if callCount != 2 {
		t.Errorf("expected 2 backend calls (one per path), got %d", callCount)
	}
}

func TestXCacheHeader_Non200NotCachedByDefault(t *testing.T) {
	t.Parallel()
	cache := newTestCache(t)

	callCount := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		w.Write([]byte(`{"error":"not found"}`))
	})

	config := DefaultResponseCacheConfig()
	handler := ResponseCacheHandler(cache, config)(backend)

	req1 := newTestRequest(t, "GET", "/api/missing", "test-404-1")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	time.Sleep(100 * time.Millisecond)

	req2 := newTestRequest(t, "GET", "/api/missing", "test-404-2")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	// 404 should not be cached by default, both should be MISS
	if rr2.Header().Get("X-Cache") != "MISS" {
		t.Errorf("404 response should not be cached, got X-Cache: %q", rr2.Header().Get("X-Cache"))
	}

	if callCount != 2 {
		t.Errorf("404: expected backend called twice, got %d", callCount)
	}
}

func TestXCacheHeader_IgnoreNoCacheOverride(t *testing.T) {
	t.Parallel()
	cache := newTestCache(t)

	callCount := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(200)
		w.Write([]byte(fmt.Sprintf(`{"count":%d}`, callCount)))
	})

	config := DefaultResponseCacheConfig()
	config.IgnoreNoCache = true // Override: cache despite no-store
	handler := ResponseCacheHandler(cache, config)(backend)

	req1 := newTestRequest(t, "GET", "/api/override-nostore", "test-override-1")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	time.Sleep(100 * time.Millisecond)

	req2 := newTestRequest(t, "GET", "/api/override-nostore", "test-override-2")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	// Should be HIT because ignore_no_cache is true
	if rr2.Header().Get("X-Cache") != "HIT" {
		t.Errorf("ignore_no_cache: expected HIT, got %q", rr2.Header().Get("X-Cache"))
	}

	// Backend should only be called once
	if callCount != 1 {
		t.Errorf("ignore_no_cache: expected backend called once, got %d", callCount)
	}

	// Response should still have original no-store header (not modified)
	if rr2.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("expected original Cache-Control: no-store preserved, got %q", rr2.Header().Get("Cache-Control"))
	}
}

func TestXCacheHeader_CachePrivateOverride(t *testing.T) {
	t.Parallel()
	cache := newTestCache(t)

	callCount := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private, max-age=300")
		w.WriteHeader(200)
		w.Write([]byte(fmt.Sprintf(`{"count":%d}`, callCount)))
	})

	config := DefaultResponseCacheConfig()
	config.CachePrivate = true // Override: cache private responses
	handler := ResponseCacheHandler(cache, config)(backend)

	req1 := newTestRequest(t, "GET", "/api/override-private", "test-private-override-1")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	time.Sleep(100 * time.Millisecond)

	req2 := newTestRequest(t, "GET", "/api/override-private", "test-private-override-2")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Header().Get("X-Cache") != "HIT" {
		t.Errorf("cache_private: expected HIT, got %q", rr2.Header().Get("X-Cache"))
	}

	if callCount != 1 {
		t.Errorf("cache_private: expected backend called once, got %d", callCount)
	}
}

func TestXCacheHeader_StoreNon200Override(t *testing.T) {
	t.Parallel()
	cache := newTestCache(t)

	callCount := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		w.Write([]byte(`{"error":"not found"}`))
	})

	config := DefaultResponseCacheConfig()
	config.StoreNon200 = true // Override: cache 404s
	handler := ResponseCacheHandler(cache, config)(backend)

	req1 := newTestRequest(t, "GET", "/api/override-404", "test-404-override-1")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	time.Sleep(100 * time.Millisecond)

	req2 := newTestRequest(t, "GET", "/api/override-404", "test-404-override-2")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Header().Get("X-Cache") != "HIT" {
		t.Errorf("store_non_200: expected HIT for cached 404, got %q", rr2.Header().Get("X-Cache"))
	}

	if rr2.Code != 404 {
		t.Errorf("cached 404 should return 404, got %d", rr2.Code)
	}

	if callCount != 1 {
		t.Errorf("store_non_200: expected backend called once, got %d", callCount)
	}
}

func TestXCacheHeader_CachedResponsePreservesHeaders(t *testing.T) {
	t.Parallel()
	cache := newTestCache(t)

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Custom", "test-value")
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.WriteHeader(200)
		w.Write([]byte(`{"data":"headers"}`))
	})

	config := DefaultResponseCacheConfig()
	handler := ResponseCacheHandler(cache, config)(backend)

	req1 := newTestRequest(t, "GET", "/api/headers", "test-headers-1")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	time.Sleep(100 * time.Millisecond)

	// Cached response should preserve original headers
	req2 := newTestRequest(t, "GET", "/api/headers", "test-headers-2")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Header().Get("X-Cache") != "HIT" {
		t.Errorf("expected HIT, got %q", rr2.Header().Get("X-Cache"))
	}

	if rr2.Header().Get("X-Custom") != "test-value" {
		t.Errorf("cached response missing X-Custom header, got %q", rr2.Header().Get("X-Custom"))
	}

	if rr2.Header().Get("Content-Type") != "application/json" {
		t.Errorf("cached response missing Content-Type, got %q", rr2.Header().Get("Content-Type"))
	}
}
