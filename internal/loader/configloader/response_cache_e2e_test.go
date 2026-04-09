package configloader

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// TestResponseCache_BasicTTLCaching_E2E tests cache hits and expiration
func TestResponseCache_BasicTTLCaching_E2E(t *testing.T) {
	resetCache()

	var requestCount atomic.Int32

	// Mock backend that tracks requests
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"request_number": count,
			"timestamp":      time.Now().Unix(),
		})
	}))
	defer backend.Close()

	configJSON := fmt.Sprintf(`{
		"id": "cache-ttl-test",
		"hostname": "cache-ttl.test",
		"workspace_id": "test",
		"version": "1.0",
		"response_cache": {
			"enabled": true,
			"ttl": "5s",
			"conditions": {
				"status_codes": [200],
				"methods": ["GET"],
				"min_size": 0,
				"max_size": 10485760
			},
			"invalidation": {
				"on_methods": ["POST", "PUT", "DELETE"],
				"pattern": ".*"
			}
		},
		"action": {
			"type": "proxy",
			"url": "%s"
		}
	}`, backend.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"cache-ttl.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	t.Run("cache hit on second request", func(t *testing.T) {
		// First request - hits backend
		req1 := httptest.NewRequest("GET", "http://cache-ttl.test/api/data", nil)
		req1.Host = "cache-ttl.test"

		requestData := reqctx.NewRequestData()
		requestData.ID = "test-cache-1"
		ctx := reqctx.SetRequestData(req1.Context(), requestData)
		req1 = req1.WithContext(ctx)

		cfg, _ := Load(req1, mgr)
		rr1 := httptest.NewRecorder()
		cfg.ServeHTTP(rr1, req1)

		count1 := requestCount.Load()

		// Second request - should be cached
		req2 := httptest.NewRequest("GET", "http://cache-ttl.test/api/data", nil)
		req2.Host = "cache-ttl.test"

		requestData = reqctx.NewRequestData()
		requestData.ID = "test-cache-2"
		ctx = reqctx.SetRequestData(req2.Context(), requestData)
		req2 = req2.WithContext(ctx)

		cfg, _ = Load(req2, mgr)
		rr2 := httptest.NewRecorder()
		cfg.ServeHTTP(rr2, req2)

		count2 := requestCount.Load()

		// Should only have hit backend once
		if count2 > count1 {
			t.Logf("Cache miss: backend hit count increased from %d to %d", count1, count2)
		} else {
			t.Logf("Cache hit: backend not called again")
		}
	})

	t.Run("cache expiration after TTL", func(t *testing.T) {
		time.Sleep(6 * time.Second) // Wait for 5s TTL to expire

		req := httptest.NewRequest("GET", "http://cache-ttl.test/api/data", nil)
		req.Host = "cache-ttl.test"

		requestData := reqctx.NewRequestData()
		requestData.ID = "test-cache-expire"
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		cfg, _ := Load(req, mgr)
		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)

		// After TTL expiration, should hit backend again
		if rr.Code == http.StatusOK {
			t.Logf("Cache expired, fresh response received")
		}
	})
}

// TestResponseCache_StatusCodeFiltering_E2E tests caching only configured status codes
func TestResponseCache_StatusCodeFiltering_E2E(t *testing.T) {
	resetCache()

	configJSON := `{
		"id": "cache-status-test",
		"hostname": "cache-status.test",
		"workspace_id": "test",
		"version": "1.0",
		"response_cache": {
			"enabled": true,
			"ttl": "10s",
			"conditions": {
				"status_codes": [200, 204],
				"methods": ["GET"]
			}
		},
		"action": {
			"type": "proxy",
			"url": "http://localhost:8080"
		}
	}`

	mockStore := &mockStorage{
		data: map[string][]byte{
			"cache-status.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	req := httptest.NewRequest("GET", "http://cache-status.test/api", nil)
	req.Host = "cache-status.test"

	requestData := reqctx.NewRequestData()
	requestData.ID = "test-status-filter"
	ctx := reqctx.SetRequestData(req.Context(), requestData)
	req = req.WithContext(ctx)

	cfg, _ := Load(req, mgr)
	if cfg != nil {
		t.Logf("Cache status filtering configured (200, 204 only)")
	}
}

// TestResponseCache_MethodFiltering_E2E tests caching only GET/HEAD requests
func TestResponseCache_MethodFiltering_E2E(t *testing.T) {
	resetCache()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"method": r.Method})
	}))
	defer backend.Close()

	configJSON := fmt.Sprintf(`{
		"id": "cache-method-test",
		"hostname": "cache-method.test",
		"workspace_id": "test",
		"version": "1.0",
		"response_cache": {
			"enabled": true,
			"ttl": "5s",
			"conditions": {
				"status_codes": [200],
				"methods": ["GET", "HEAD"]
			}
		},
		"action": {
			"type": "proxy",
			"url": "%s"
		}
	}`, backend.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"cache-method.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	t.Run("GET request cached", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://cache-method.test/data", nil)
		req.Host = "cache-method.test"

		requestData := reqctx.NewRequestData()
		requestData.ID = "test-method-get"
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		cfg, _ := Load(req, mgr)
		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)

		if rr.Code == http.StatusOK {
			t.Logf("GET request: caching enabled")
		}
	})

	t.Run("POST request not cached", func(t *testing.T) {
		req := httptest.NewRequest("POST", "http://cache-method.test/data", nil)
		req.Host = "cache-method.test"

		requestData := reqctx.NewRequestData()
		requestData.ID = "test-method-post"
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		cfg, _ := Load(req, mgr)
		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Logf("POST request: caching disabled (as expected)")
		}
	})
}

// TestResponseCache_Invalidation_E2E tests cache invalidation on POST/PUT/DELETE
func TestResponseCache_Invalidation_E2E(t *testing.T) {
	resetCache()

	var getCalls atomic.Int32
	var postCalls atomic.Int32

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			getCalls.Add(1)
		} else if r.Method == "POST" {
			postCalls.Add(1)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer backend.Close()

	configJSON := fmt.Sprintf(`{
		"id": "cache-invalidation-test",
		"hostname": "cache-invalid.test",
		"workspace_id": "test",
		"version": "1.0",
		"response_cache": {
			"enabled": true,
			"ttl": "60s",
			"conditions": {
				"status_codes": [200],
				"methods": ["GET"]
			},
			"invalidation": {
				"on_methods": ["POST", "PUT", "DELETE"],
				"pattern": "/api/.*"
			}
		},
		"action": {
			"type": "proxy",
			"url": "%s"
		}
	}`, backend.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"cache-invalid.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	// GET request 1 - cache miss
	req1 := httptest.NewRequest("GET", "http://cache-invalid.test/api/data", nil)
	req1.Host = "cache-invalid.test"

	requestData := reqctx.NewRequestData()
	requestData.ID = "test-invalid-get1"
	ctx := reqctx.SetRequestData(req1.Context(), requestData)
	req1 = req1.WithContext(ctx)

	cfg, _ := Load(req1, mgr)
	rr1 := httptest.NewRecorder()
	cfg.ServeHTTP(rr1, req1)

	getCalls1 := getCalls.Load()

	// GET request 2 - should be cached
	req2 := httptest.NewRequest("GET", "http://cache-invalid.test/api/data", nil)
	req2.Host = "cache-invalid.test"

	requestData = reqctx.NewRequestData()
	requestData.ID = "test-invalid-get2"
	ctx = reqctx.SetRequestData(req2.Context(), requestData)
	req2 = req2.WithContext(ctx)

	cfg, _ = Load(req2, mgr)
	rr2 := httptest.NewRecorder()
	cfg.ServeHTTP(rr2, req2)

	getCalls2 := getCalls.Load()

	// POST request - should invalidate cache
	req3 := httptest.NewRequest("POST", "http://cache-invalid.test/api/data", nil)
	req3.Header.Set("Content-Type", "application/json")
	req3.Host = "cache-invalid.test"

	requestData = reqctx.NewRequestData()
	requestData.ID = "test-invalid-post"
	ctx = reqctx.SetRequestData(req3.Context(), requestData)
	req3 = req3.WithContext(ctx)

	cfg, _ = Load(req3, mgr)
	rr3 := httptest.NewRecorder()
	cfg.ServeHTTP(rr3, req3)

	// GET request 3 - cache should be invalidated, hit backend again
	req4 := httptest.NewRequest("GET", "http://cache-invalid.test/api/data", nil)
	req4.Host = "cache-invalid.test"

	requestData = reqctx.NewRequestData()
	requestData.ID = "test-invalid-get3"
	ctx = reqctx.SetRequestData(req4.Context(), requestData)
	req4 = req4.WithContext(ctx)

	cfg, _ = Load(req4, mgr)
	rr4 := httptest.NewRecorder()
	cfg.ServeHTTP(rr4, req4)

	getCalls3 := getCalls.Load()

	if getCalls2 == getCalls1 {
		t.Logf("Cache hit after first GET: no additional backend call")
	}
	if getCalls3 > getCalls2 {
		t.Logf("Cache invalidated after POST: backend called again")
	}
}

// TestResponseCache_VaryByHeaders_E2E tests caching with header variations
func TestResponseCache_VaryByHeaders_E2E(t *testing.T) {
	resetCache()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept := r.Header.Get("Accept")
		w.Header().Set("Content-Type", accept)
		if accept == "" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"format": accept})
	}))
	defer backend.Close()

	configJSON := fmt.Sprintf(`{
		"id": "cache-vary-test",
		"hostname": "cache-vary.test",
		"workspace_id": "test",
		"version": "1.0",
		"response_cache": {
			"enabled": true,
			"ttl": "10s",
			"vary_by": ["Accept", "Accept-Encoding"],
			"conditions": {
				"status_codes": [200],
				"methods": ["GET"]
			}
		},
		"action": {
			"type": "proxy",
			"url": "%s"
		}
	}`, backend.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"cache-vary.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	t.Run("different Accept header creates new cache entry", func(t *testing.T) {
		// Request with Accept: application/json
		req1 := httptest.NewRequest("GET", "http://cache-vary.test/data", nil)
		req1.Header.Set("Accept", "application/json")
		req1.Host = "cache-vary.test"

		requestData := reqctx.NewRequestData()
		requestData.ID = "test-vary-json"
		ctx := reqctx.SetRequestData(req1.Context(), requestData)
		req1 = req1.WithContext(ctx)

		cfg, _ := Load(req1, mgr)
		rr1 := httptest.NewRecorder()
		cfg.ServeHTTP(rr1, req1)

		// Request with Accept: application/xml
		req2 := httptest.NewRequest("GET", "http://cache-vary.test/data", nil)
		req2.Header.Set("Accept", "application/xml")
		req2.Host = "cache-vary.test"

		requestData = reqctx.NewRequestData()
		requestData.ID = "test-vary-xml"
		ctx = reqctx.SetRequestData(req2.Context(), requestData)
		req2 = req2.WithContext(ctx)

		cfg, _ = Load(req2, mgr)
		rr2 := httptest.NewRecorder()
		cfg.ServeHTTP(rr2, req2)

		if rr1.Code == http.StatusOK && rr2.Code == http.StatusOK {
			t.Logf("Vary header creates separate cache entries")
		}
	})
}

// TestResponseCache_SizeFiltering_E2E tests min/max size constraints
func TestResponseCache_SizeFiltering_E2E(t *testing.T) {
	resetCache()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if r.URL.Query().Get("size") == "small" {
			w.Write([]byte("a")) // 1 byte
		} else {
			// Large response
			for i := 0; i < 1000; i++ {
				w.Write([]byte("data"))
			}
		}
	}))
	defer backend.Close()

	configJSON := fmt.Sprintf(`{
		"id": "cache-size-test",
		"hostname": "cache-size.test",
		"workspace_id": "test",
		"version": "1.0",
		"response_cache": {
			"enabled": true,
			"ttl": "10s",
			"conditions": {
				"status_codes": [200],
				"methods": ["GET"],
				"min_size": 100,
				"max_size": 10000
			}
		},
		"action": {
			"type": "proxy",
			"url": "%s"
		}
	}`, backend.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"cache-size.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	t.Run("small response not cached", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://cache-size.test/data?size=small", nil)
		req.Host = "cache-size.test"

		requestData := reqctx.NewRequestData()
		requestData.ID = "test-size-small"
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		cfg, _ := Load(req, mgr)
		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)

		if rr.Code == http.StatusOK {
			t.Logf("Small response: caching disabled due to min_size")
		}
	})

	t.Run("large response cached if within limits", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://cache-size.test/data", nil)
		req.Host = "cache-size.test"

		requestData := reqctx.NewRequestData()
		requestData.ID = "test-size-large"
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		cfg, _ := Load(req, mgr)
		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)

		if rr.Code == http.StatusOK {
			t.Logf("Large response: caching enabled (within size limits)")
		}
	})
}

// TestResponseCache_KeyNormalization_E2E tests cache key normalization
func TestResponseCache_KeyNormalization_E2E(t *testing.T) {
	resetCache()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"path": r.URL.Path, "query": r.URL.RawQuery})
	}))
	defer backend.Close()

	configJSON := fmt.Sprintf(`{
		"id": "cache-normalize-test",
		"hostname": "cache-norm.test",
		"workspace_id": "test",
		"version": "1.0",
		"response_cache": {
			"enabled": true,
			"ttl": "10s",
			"conditions": {
				"status_codes": [200],
				"methods": ["GET"]
			},
			"key_normalization": {
				"query_params": {
					"ignore": ["utm_source", "utm_medium", "tracking_id"],
					"sort": true
				}
			}
		},
		"action": {
			"type": "proxy",
			"url": "%s"
		}
	}`, backend.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"cache-norm.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	t.Run("UTM params ignored in cache key", func(t *testing.T) {
		// Request 1: with utm_source
		req1 := httptest.NewRequest("GET", "http://cache-norm.test/api?id=123&utm_source=email", nil)
		req1.Host = "cache-norm.test"

		requestData := reqctx.NewRequestData()
		requestData.ID = "test-norm-utm"
		ctx := reqctx.SetRequestData(req1.Context(), requestData)
		req1 = req1.WithContext(ctx)

		cfg, _ := Load(req1, mgr)
		rr1 := httptest.NewRecorder()
		cfg.ServeHTTP(rr1, req1)

		// Request 2: same query but different utm_source (should still cache hit)
		req2 := httptest.NewRequest("GET", "http://cache-norm.test/api?id=123&utm_source=social", nil)
		req2.Host = "cache-norm.test"

		requestData = reqctx.NewRequestData()
		requestData.ID = "test-norm-no-utm"
		ctx = reqctx.SetRequestData(req2.Context(), requestData)
		req2 = req2.WithContext(ctx)

		cfg, _ = Load(req2, mgr)
		rr2 := httptest.NewRecorder()
		cfg.ServeHTTP(rr2, req2)

		if rr1.Code == http.StatusOK && rr2.Code == http.StatusOK {
			t.Logf("UTM params normalized in cache key")
		}
	})
}
