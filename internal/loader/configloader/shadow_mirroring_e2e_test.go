package configloader

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// TestShadowMirroring_BasicMirroring_E2E tests that shadow transport mirrors traffic to an upstream target
func TestShadowMirroring_BasicMirroring_E2E(t *testing.T) {
	resetCache()

	// Create shadow server that records requests
	var shadowCount atomic.Int32
	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shadowCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowServer.Close()

	// Create primary server
	primaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer primaryServer.Close()

	// Create config with shadow transport
	configJSON := `{
		"id": "shadow-mirror-test",
		"hostname": "shadow-mirror.test",
		"workspace_id": "test",
		"version": "1.0",
		"action": {
			"type": "proxy",
			"url": "` + primaryServer.URL + `",
			"shadow": {
				"upstream_url": "` + shadowServer.URL + `",
				"sample_rate": 1.0
			}
		}
	}`

	mockStore := &mockStorage{
		data: map[string][]byte{
			"shadow-mirror.test": []byte(configJSON),
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

	// Make requests through the config handler
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "http://shadow-mirror.test/test/path", nil)
		req.Host = "shadow-mirror.test"

		requestData := reqctx.NewRequestData()
		requestData.ID = "test-shadow-id-" + fmt.Sprintf("%d", i)
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Request %d: failed to load config: %v", i, err)
		}

		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Request %d: expected 200, got %d", i, rr.Code)
		}
	}

	// Wait for shadow requests to arrive
	time.Sleep(150 * time.Millisecond)

	// Check that shadow received all 3 requests
	if shadowCount.Load() != 3 {
		t.Errorf("Expected 3 shadow requests, got %d", shadowCount.Load())
	}
}

// TestShadowMirroring_SampleRate_E2E tests that sample rate controls request mirroring
func TestShadowMirroring_SampleRate_E2E(t *testing.T) {
	resetCache()

	// Create shadow server with atomic counter
	var shadowCount atomic.Int32
	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shadowCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowServer.Close()

	// Create primary server
	primaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer primaryServer.Close()

	// Create config with 50% sample rate
	configJSON := `{
		"id": "shadow-sample-test",
		"hostname": "shadow-sample.test",
		"workspace_id": "test",
		"version": "1.0",
		"action": {
			"type": "proxy",
			"url": "` + primaryServer.URL + `",
			"shadow": {
				"upstream_url": "` + shadowServer.URL + `",
				"sample_rate": 0.5
			}
		}
	}`

	mockStore := &mockStorage{
		data: map[string][]byte{
			"shadow-sample.test": []byte(configJSON),
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

	// Send 200 requests
	for i := 0; i < 200; i++ {
		req := httptest.NewRequest("GET", "http://shadow-sample.test/test", nil)
		req.Host = "shadow-sample.test"

		requestData := reqctx.NewRequestData()
		requestData.ID = fmt.Sprintf("test-sample-%d", i)
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}

		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)
	}

	// Wait for shadow requests
	time.Sleep(300 * time.Millisecond)

	count := int(shadowCount.Load())
	// Expect roughly 50% (100 requests), allow 30% variance (70-130)
	if count < 70 || count > 130 {
		t.Errorf("Expected shadow requests in range [70, 130], got %d", count)
	}
}

// TestShadowMirroring_HeaderModifiers_E2E tests that shadow modifiers apply to shadow requests
func TestShadowMirroring_HeaderModifiers_E2E(t *testing.T) {
	resetCache()

	// Create shadow server that checks received headers
	var receivedHeaders http.Header
	var mu sync.Mutex
	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedHeaders = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowServer.Close()

	// Create primary server
	primaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer primaryServer.Close()

	// Create config with header modifiers
	configJSON := `{
		"id": "shadow-headers-test",
		"hostname": "shadow-headers.test",
		"workspace_id": "test",
		"version": "1.0",
		"action": {
			"type": "proxy",
			"url": "` + primaryServer.URL + `",
			"shadow": {
				"upstream_url": "` + shadowServer.URL + `",
				"sample_rate": 1.0,
				"modifiers": [
					{
						"headers": {
							"set": {"X-Shadow": "yes"},
							"remove": ["Authorization"]
						}
					}
				]
			}
		}
	}`

	mockStore := &mockStorage{
		data: map[string][]byte{
			"shadow-headers.test": []byte(configJSON),
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

	// Send request with Authorization header
	req := httptest.NewRequest("GET", "http://shadow-headers.test/test", nil)
	req.Host = "shadow-headers.test"
	req.Header.Set("Authorization", "Bearer token123")

	requestData := reqctx.NewRequestData()
	requestData.ID = "test-headers"
	ctx := reqctx.SetRequestData(req.Context(), requestData)
	req = req.WithContext(ctx)

	cfg, err := Load(req, mgr)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	rr := httptest.NewRecorder()
	cfg.ServeHTTP(rr, req)

	// Wait for shadow request
	time.Sleep(100 * time.Millisecond)

	// Check shadow received modified headers
	mu.Lock()
	defer mu.Unlock()
	if v := receivedHeaders.Get("X-Shadow"); v != "yes" {
		t.Errorf("Expected X-Shadow: yes, got %q", v)
	}
	if v := receivedHeaders.Get("Authorization"); v != "" {
		t.Errorf("Expected Authorization removed, got %q", v)
	}
}

// TestShadowMirroring_PrimaryUnaffectedByShadowFailure_E2E tests that primary request succeeds even if shadow fails
func TestShadowMirroring_PrimaryUnaffectedByShadowFailure_E2E(t *testing.T) {
	resetCache()

	// Create shadow server that returns 500 with delay
	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer shadowServer.Close()

	// Create primary server
	primaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer primaryServer.Close()

	// Create config with fail_on_error: false and short timeout
	configJSON := `{
		"id": "shadow-fail-test",
		"hostname": "shadow-fail.test",
		"workspace_id": "test",
		"version": "1.0",
		"action": {
			"type": "proxy",
			"url": "` + primaryServer.URL + `",
			"shadow": {
				"upstream_url": "` + shadowServer.URL + `",
				"sample_rate": 1.0,
				"fail_on_error": false,
				"timeout": "50ms"
			}
		}
	}`

	mockStore := &mockStorage{
		data: map[string][]byte{
			"shadow-fail.test": []byte(configJSON),
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

	// Send 5 requests - all should succeed at primary
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "http://shadow-fail.test/test", nil)
		req.Host = "shadow-fail.test"

		requestData := reqctx.NewRequestData()
		requestData.ID = fmt.Sprintf("test-fail-%d", i)
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Request %d failed to load: %v", i, err)
		}

		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Request %d: expected 200, got %d", i, rr.Code)
		}
	}
}

// TestShadowMirroring_MaxBodySize_E2E tests that shadow respects max body size limit
func TestShadowMirroring_MaxBodySize_E2E(t *testing.T) {
	resetCache()

	// Create shadow server with atomic counter
	var shadowCount atomic.Int32
	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shadowCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowServer.Close()

	// Create primary server
	primaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer primaryServer.Close()

	// Create config with max_body_size: "100" bytes
	configJSON := `{
		"id": "shadow-maxbody-test",
		"hostname": "shadow-maxbody.test",
		"workspace_id": "test",
		"version": "1.0",
		"action": {
			"type": "proxy",
			"url": "` + primaryServer.URL + `",
			"shadow": {
				"upstream_url": "` + shadowServer.URL + `",
				"sample_rate": 1.0,
				"max_body_size": "100"
			}
		}
	}`

	mockStore := &mockStorage{
		data: map[string][]byte{
			"shadow-maxbody.test": []byte(configJSON),
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

	// Send POST with 10-byte body (should be mirrored)
	req1 := httptest.NewRequest("POST", "http://shadow-maxbody.test/test", nil)
	req1.Header.Set("Content-Type", "application/json")
	req1.Host = "shadow-maxbody.test"
	req1.ContentLength = int64(len("1234567890"))

	requestData := reqctx.NewRequestData()
	requestData.ID = "test-small-body"
	ctx := reqctx.SetRequestData(req1.Context(), requestData)
	req1 = req1.WithContext(ctx)

	cfg, _ := Load(req1, mgr)
	rr1 := httptest.NewRecorder()
	cfg.ServeHTTP(rr1, req1)

	time.Sleep(50 * time.Millisecond)
	count1 := shadowCount.Load()

	// Send POST with 200-byte body (should be dropped by shadow)
	bigBody := make([]byte, 200)
	for i := range bigBody {
		bigBody[i] = 'a'
	}
	req2 := httptest.NewRequest("POST", "http://shadow-maxbody.test/test", nil)
	req2.Header.Set("Content-Type", "application/json")
	req2.Host = "shadow-maxbody.test"
	req2.ContentLength = int64(len(bigBody))

	requestData = reqctx.NewRequestData()
	requestData.ID = "test-large-body"
	ctx = reqctx.SetRequestData(req2.Context(), requestData)
	req2 = req2.WithContext(ctx)

	cfg, _ = Load(req2, mgr)
	rr2 := httptest.NewRecorder()
	cfg.ServeHTTP(rr2, req2)

	time.Sleep(50 * time.Millisecond)
	count2 := shadowCount.Load()

	// First should be mirrored, second should be dropped
	if count1 != 1 {
		t.Errorf("Expected 1 shadow request after small body, got %d", count1)
	}
	if count2 != 1 {
		t.Errorf("Expected no new shadow request after large body (still %d), got %d", count1, count2)
	}
}

// TestShadowMirroring_CircuitBreaker_E2E tests shadow circuit breaker functionality
func TestShadowMirroring_CircuitBreaker_E2E(t *testing.T) {
	resetCache()

	// Create shadow server that returns 500 for first 6 requests, then 200
	var requestCount atomic.Int32
	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := requestCount.Add(1)
		if count <= 6 {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer shadowServer.Close()

	// Create primary server
	primaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer primaryServer.Close()

	// Create config with circuit breaker (failure_threshold: 3, timeout: 200ms)
	configJSON := `{
		"id": "shadow-cb-test",
		"hostname": "shadow-cb.test",
		"workspace_id": "test",
		"version": "1.0",
		"action": {
			"type": "proxy",
			"url": "` + primaryServer.URL + `",
			"shadow": {
				"upstream_url": "` + shadowServer.URL + `",
				"sample_rate": 1.0,
				"circuit_breaker": {
					"failure_threshold": 3,
					"success_threshold": 2,
					"timeout": "200ms"
				}
			}
		}
	}`

	mockStore := &mockStorage{
		data: map[string][]byte{
			"shadow-cb.test": []byte(configJSON),
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

	// Send 10 quick requests (CB opens after 3 failures, drops rest)
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "http://shadow-cb.test/test", nil)
		req.Host = "shadow-cb.test"

		requestData := reqctx.NewRequestData()
		requestData.ID = fmt.Sprintf("test-cb-1-%d", i)
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		cfg, _ := Load(req, mgr)
		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Primary should always return 200, got %d", rr.Code)
		}
	}

	count1 := requestCount.Load()
	if count1 < 3 {
		t.Errorf("Expected at least 3 shadow requests before CB opens, got %d", count1)
	}

	// Wait for CB timeout to expire
	time.Sleep(250 * time.Millisecond)

	// Send 3 more requests (CB should recover)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "http://shadow-cb.test/test", nil)
		req.Host = "shadow-cb.test"

		requestData := reqctx.NewRequestData()
		requestData.ID = fmt.Sprintf("test-cb-2-%d", i)
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		cfg, _ := Load(req, mgr)
		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)
	}

	time.Sleep(100 * time.Millisecond)

	count2 := requestCount.Load()
	if count2 <= count1 {
		t.Errorf("Expected new shadow requests after CB recovery, got same count %d", count2)
	}
}
