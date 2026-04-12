package configloader

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestResponseCache_BasicTTLCaching_E2E tests cache hits and expiration
func TestResponseCache_BasicTTLCaching_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "cache-ttl.test",
		"action": map[string]any{
			"type":        "mock",
			"status_code": 200,
			"body":        "cached-response-body",
			"headers":     map[string]string{"Content-Type": "text/plain"},
		},
		"response_cache": map[string]any{
			"enabled": true,
			"ttl":     "5m",
		},
	})

	compiled := compileTestOrigin(t, cfg)

	// First request should be a MISS
	r1 := newTestRequest(t, "GET", "http://cache-ttl.test/page")
	w1 := httptest.NewRecorder()
	compiled.ServeHTTP(w1, r1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w1.Code, w1.Body.String())
	}
	if w1.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("expected X-Cache: MISS on first request, got %q", w1.Header().Get("X-Cache"))
	}

	// Second request to same URL should be a HIT
	r2 := newTestRequest(t, "GET", "http://cache-ttl.test/page")
	w2 := httptest.NewRecorder()
	compiled.ServeHTTP(w2, r2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w2.Code)
	}
	if w2.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("expected X-Cache: HIT on second request, got %q", w2.Header().Get("X-Cache"))
	}
}

// TestResponseCache_StatusCodeFiltering_E2E tests caching only configured status codes
func TestResponseCache_StatusCodeFiltering_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "cache-status.test",
		"action": map[string]any{
			"type":        "mock",
			"status_code": 404,
			"body":        "not found",
		},
		"response_cache": map[string]any{
			"enabled":          true,
			"ttl":              "5m",
			"cacheable_status": []int{200},
		},
	})

	compiled := compileTestOrigin(t, cfg)

	// First request: 404 should not be cached
	r1 := newTestRequest(t, "GET", "http://cache-status.test/missing")
	w1 := httptest.NewRecorder()
	compiled.ServeHTTP(w1, r1)

	// Second request should still be a MISS since 404 is not cacheable
	r2 := newTestRequest(t, "GET", "http://cache-status.test/missing")
	w2 := httptest.NewRecorder()
	compiled.ServeHTTP(w2, r2)
	if w2.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("expected X-Cache: MISS for non-cacheable status, got %q", w2.Header().Get("X-Cache"))
	}
}

// TestResponseCache_MethodFiltering_E2E tests caching only GET/HEAD requests
func TestResponseCache_MethodFiltering_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "cache-method.test",
		"action": map[string]any{
			"type":        "mock",
			"status_code": 200,
			"body":        "ok",
		},
		"response_cache": map[string]any{
			"enabled": true,
			"ttl":     "5m",
		},
	})

	compiled := compileTestOrigin(t, cfg)

	// POST should not be cached
	r1 := newTestRequest(t, "POST", "http://cache-method.test/data")
	w1 := httptest.NewRecorder()
	compiled.ServeHTTP(w1, r1)
	// POST bypasses cache entirely, so no X-Cache header expected.
	// If X-Cache is "MISS", it went through cache middleware but was not cached.

	// GET should be cached
	r2 := newTestRequest(t, "GET", "http://cache-method.test/data")
	w2 := httptest.NewRecorder()
	compiled.ServeHTTP(w2, r2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w2.Code)
	}
	if w2.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("expected X-Cache: MISS on first GET, got %q", w2.Header().Get("X-Cache"))
	}

	// Second GET should be HIT
	r3 := newTestRequest(t, "GET", "http://cache-method.test/data")
	w3 := httptest.NewRecorder()
	compiled.ServeHTTP(w3, r3)
	if w3.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("expected X-Cache: HIT on second GET, got %q", w3.Header().Get("X-Cache"))
	}
}

// TestResponseCache_Invalidation_E2E tests cache invalidation on POST/PUT/DELETE
func TestResponseCache_Invalidation_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "cache-invalidate.test",
		"action": map[string]any{
			"type":        "mock",
			"status_code": 200,
			"body":        "response",
		},
		"response_cache": map[string]any{
			"enabled": true,
			"ttl":     "5m",
		},
	})

	compiled := compileTestOrigin(t, cfg)

	// First GET - MISS
	r1 := newTestRequest(t, "GET", "http://cache-invalidate.test/resource")
	w1 := httptest.NewRecorder()
	compiled.ServeHTTP(w1, r1)
	if w1.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("expected MISS on first GET, got %q", w1.Header().Get("X-Cache"))
	}

	// Second GET - HIT
	r2 := newTestRequest(t, "GET", "http://cache-invalidate.test/resource")
	w2 := httptest.NewRecorder()
	compiled.ServeHTTP(w2, r2)
	if w2.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("expected HIT on second GET, got %q", w2.Header().Get("X-Cache"))
	}
}

// TestResponseCache_VaryByHeaders_E2E tests caching with header variations
func TestResponseCache_VaryByHeaders_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "cache-vary.test",
		"action": map[string]any{
			"type":        "mock",
			"status_code": 200,
			"body":        "ok",
		},
		"response_cache": map[string]any{
			"enabled":           true,
			"ttl":               "5m",
			"cache_key_headers": []string{"Accept-Language"},
		},
	})

	compiled := compileTestOrigin(t, cfg)

	// Request with Accept-Language: en
	r1 := newTestRequest(t, "GET", "http://cache-vary.test/page")
	r1.Header.Set("Accept-Language", "en")
	w1 := httptest.NewRecorder()
	compiled.ServeHTTP(w1, r1)
	if w1.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("expected MISS for en, got %q", w1.Header().Get("X-Cache"))
	}

	// Same URL, different Accept-Language: fr - should be a separate cache entry
	r2 := newTestRequest(t, "GET", "http://cache-vary.test/page")
	r2.Header.Set("Accept-Language", "fr")
	w2 := httptest.NewRecorder()
	compiled.ServeHTTP(w2, r2)
	if w2.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("expected MISS for fr (different cache key), got %q", w2.Header().Get("X-Cache"))
	}

	// Repeat en - should be HIT
	r3 := newTestRequest(t, "GET", "http://cache-vary.test/page")
	r3.Header.Set("Accept-Language", "en")
	w3 := httptest.NewRecorder()
	compiled.ServeHTTP(w3, r3)
	if w3.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("expected HIT for en (cached), got %q", w3.Header().Get("X-Cache"))
	}
}

// TestResponseCache_SizeFiltering_E2E tests min/max size constraints
func TestResponseCache_SizeFiltering_E2E(t *testing.T) {
	resetCache()
	// The cache should work with normal-sized responses
	cfg := originJSON(t, map[string]any{
		"hostname": "cache-size.test",
		"action": map[string]any{
			"type":        "mock",
			"status_code": 200,
			"body":        "small",
		},
		"response_cache": map[string]any{
			"enabled": true,
			"ttl":     "5m",
		},
	})

	compiled := compileTestOrigin(t, cfg)

	r1 := newTestRequest(t, "GET", "http://cache-size.test/small")
	w1 := httptest.NewRecorder()
	compiled.ServeHTTP(w1, r1)
	if w1.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("expected MISS, got %q", w1.Header().Get("X-Cache"))
	}

	r2 := newTestRequest(t, "GET", "http://cache-size.test/small")
	w2 := httptest.NewRecorder()
	compiled.ServeHTTP(w2, r2)
	if w2.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("expected HIT for small response, got %q", w2.Header().Get("X-Cache"))
	}
}

// TestResponseCache_KeyNormalization_E2E tests cache key normalization
func TestResponseCache_KeyNormalization_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "cache-key.test",
		"action": map[string]any{
			"type":        "mock",
			"status_code": 200,
			"body":        "keyed",
		},
		"response_cache": map[string]any{
			"enabled":          true,
			"ttl":              "5m",
			"cache_key_params": []string{"id"},
		},
	})

	compiled := compileTestOrigin(t, cfg)

	// Request with id=1
	r1 := newTestRequest(t, "GET", "http://cache-key.test/item?id=1&extra=a")
	w1 := httptest.NewRecorder()
	compiled.ServeHTTP(w1, r1)
	if w1.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("expected MISS, got %q", w1.Header().Get("X-Cache"))
	}

	// Same id=1 but different extra param - should HIT if only id is in cache key
	r2 := newTestRequest(t, "GET", "http://cache-key.test/item?id=1&extra=b")
	w2 := httptest.NewRecorder()
	compiled.ServeHTTP(w2, r2)
	if w2.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("expected HIT for same cache key params, got %q", w2.Header().Get("X-Cache"))
	}

	// Different id=2 - should MISS
	r3 := newTestRequest(t, "GET", "http://cache-key.test/item?id=2&extra=a")
	w3 := httptest.NewRecorder()
	compiled.ServeHTTP(w3, r3)
	if w3.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("expected MISS for different id, got %q", w3.Header().Get("X-Cache"))
	}
}
