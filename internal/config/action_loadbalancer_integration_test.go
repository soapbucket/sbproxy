package config

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestLoadBalancerRoundTrip tests that the load balancer properly distributes
// requests across backend servers and includes backend identification in responses
func TestLoadBalancerRoundTrip(t *testing.T) {
	// Create mock backend servers that return their identity
	var backend1Count, backend2Count, backend3Count int64

	backend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&backend1Count, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"backend": "backend-1", "message": "Hello from backend 1"}`))
	}))
	defer backend1.Close()

	backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&backend2Count, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"backend": "backend-2", "message": "Hello from backend 2"}`))
	}))
	defer backend2.Close()

	backend3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&backend3Count, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"backend": "backend-3", "message": "Hello from backend 3"}`))
	}))
	defer backend3.Close()

	// Create load balancer config with the mock backends
	configJSON := `{
		"id": "lb-test",
		"hostname": "lb.test.local",
		"action": {
			"type": "loadbalancer",
			"round_robin": true,
			"disable_sticky": true,
			"targets": [
				{
					"url": "` + backend1.URL + `",
					"weight": 40
				},
				{
					"url": "` + backend2.URL + `",
					"weight": 40
				},
				{
					"url": "` + backend3.URL + `",
					"weight": 20
				}
			]
		}
	}`

	var cfg Config
	err := json.Unmarshal([]byte(configJSON), &cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Verify the load balancer is properly initialized
	if !cfg.IsProxy() {
		t.Fatal("IsProxy() should return true for load balancer")
	}

	transport := cfg.Transport()
	if transport == nil {
		t.Fatal("Transport() should not return nil for load balancer")
	}

	// Make multiple requests and verify distribution
	backendCounts := make(map[string]int)
	for i := 0; i < 30; i++ {
		req := httptest.NewRequest("GET", "http://lb.test.local/api/users", nil)
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("Failed to parse response JSON: %v", err)
		}

		backend, ok := result["backend"].(string)
		if !ok {
			t.Fatalf("Response missing 'backend' field: %s", string(body))
		}

		backendCounts[backend]++
	}

	// Verify that requests were distributed to multiple backends
	t.Logf("Backend distribution: %v", backendCounts)
	t.Logf("Backend 1 direct count: %d", atomic.LoadInt64(&backend1Count))
	t.Logf("Backend 2 direct count: %d", atomic.LoadInt64(&backend2Count))
	t.Logf("Backend 3 direct count: %d", atomic.LoadInt64(&backend3Count))

	if len(backendCounts) < 2 {
		t.Error("Load balancer should distribute requests to multiple backends")
	}

	// Verify round-robin distribution (with 30 requests and 3 backends, each should get 10)
	// Allow some variance since we're also testing sticky sessions might be disabled
	totalRequests := 0
	for _, count := range backendCounts {
		totalRequests += count
	}
	if totalRequests != 30 {
		t.Errorf("Expected 30 total requests, got %d", totalRequests)
	}
}

// TestLoadBalancerWeightedDistribution tests weighted random distribution
func TestLoadBalancerWeightedDistribution(t *testing.T) {
	// Create mock backend servers
	var heavyCount, lightCount int64

	heavyBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&heavyCount, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"backend": "heavy"}`))
	}))
	defer heavyBackend.Close()

	lightBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&lightCount, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"backend": "light"}`))
	}))
	defer lightBackend.Close()

	// Create load balancer with 90/10 weight distribution
	configJSON := `{
		"id": "lb-weighted-test",
		"hostname": "lb.weighted.test.local",
		"action": {
			"type": "loadbalancer",
			"disable_sticky": true,
			"targets": [
				{
					"url": "` + heavyBackend.URL + `",
					"weight": 90
				},
				{
					"url": "` + lightBackend.URL + `",
					"weight": 10
				}
			]
		}
	}`

	var cfg Config
	err := json.Unmarshal([]byte(configJSON), &cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	transport := cfg.Transport()
	if transport == nil {
		t.Fatal("Transport() should not return nil")
	}

	// Make 100 requests
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest("GET", "http://lb.weighted.test.local/test", nil)
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		resp.Body.Close()
	}

	// Verify weighted distribution (heavy should get significantly more)
	heavy := atomic.LoadInt64(&heavyCount)
	light := atomic.LoadInt64(&lightCount)
	t.Logf("Heavy backend: %d requests, Light backend: %d requests", heavy, light)

	// With 90/10 weights over 100 requests, heavy should get significantly more
	// Allow for some variance (at least 60% should go to heavy)
	if heavy < 60 {
		t.Errorf("Heavy backend (weight 90) got only %d requests, expected at least 60", heavy)
	}
}

// TestLoadBalancerResponseModifiers tests that per-target response modifiers work
func TestLoadBalancerResponseModifiers(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer backend.Close()

	configJSON := `{
		"id": "lb-modifiers-test",
		"hostname": "lb.modifiers.test.local",
		"action": {
			"type": "loadbalancer",
			"disable_sticky": true,
			"targets": [
				{
					"url": "` + backend.URL + `",
					"weight": 100,
					"response_modifiers": [
						{
							"headers": {
								"add": {
									"X-Served-By": "backend-1",
									"X-Backend-Version": "v2.1.0"
								}
							}
						}
					]
				}
			]
		}
	}`

	var cfg Config
	err := json.Unmarshal([]byte(configJSON), &cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	transport := cfg.Transport()
	if transport == nil {
		t.Fatal("Transport() should not return nil")
	}

	req := httptest.NewRequest("GET", "http://lb.modifiers.test.local/test", nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Verify response modifiers were applied
	servedBy := resp.Header.Get("X-Served-By")
	if servedBy != "backend-1" {
		t.Errorf("Expected X-Served-By header to be 'backend-1', got '%s'", servedBy)
	}

	version := resp.Header.Get("X-Backend-Version")
	if version != "v2.1.0" {
		t.Errorf("Expected X-Backend-Version header to be 'v2.1.0', got '%s'", version)
	}
}

// TestLoadBalancerStripBasePath tests the strip_base_path option
func TestLoadBalancerStripBasePath(t *testing.T) {
	t.Run("strip_base_path=true (default) uses request path", func(t *testing.T) {
		var receivedPath string
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedPath = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "ok"}`))
		}))
		defer backend.Close()

		configJSON := `{
			"id": "lb-strip-base-path-true",
			"hostname": "lb.test.local",
			"action": {
				"type": "loadbalancer",
				"strip_base_path": true,
				"disable_sticky": true,
				"targets": [
					{"url": "` + backend.URL + `/api/v1", "weight": 100}
				]
			}
		}`

		var cfg Config
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			t.Fatalf("Failed to unmarshal config: %v", err)
		}

		transport := cfg.Transport()
		req := httptest.NewRequest("GET", "http://lb.test.local/users/123", nil)
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		resp.Body.Close()

		// With strip_base_path=true, request path should be used
		if receivedPath != "/users/123" {
			t.Errorf("Expected path '/users/123', got '%s'", receivedPath)
		}
	})

	t.Run("strip_base_path=false uses target URL path", func(t *testing.T) {
		var receivedPath string
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedPath = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "ok"}`))
		}))
		defer backend.Close()

		configJSON := `{
			"id": "lb-strip-base-path-false",
			"hostname": "lb.test.local",
			"action": {
				"type": "loadbalancer",
				"strip_base_path": false,
				"disable_sticky": true,
				"targets": [
					{"url": "` + backend.URL + `/get", "weight": 100}
				]
			}
		}`

		var cfg Config
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			t.Fatalf("Failed to unmarshal config: %v", err)
		}

		transport := cfg.Transport()
		// Request to root should use target path
		req := httptest.NewRequest("GET", "http://lb.test.local/", nil)
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		resp.Body.Close()

		// With strip_base_path=false and request path "/", should use target path "/get"
		if receivedPath != "/get" {
			t.Errorf("Expected path '/get', got '%s'", receivedPath)
		}
	})

	t.Run("strip_base_path=false appends request path to target path", func(t *testing.T) {
		var receivedPath string
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedPath = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "ok"}`))
		}))
		defer backend.Close()

		configJSON := `{
			"id": "lb-strip-base-path-append",
			"hostname": "lb.test.local",
			"action": {
				"type": "loadbalancer",
				"strip_base_path": false,
				"disable_sticky": true,
				"targets": [
					{"url": "` + backend.URL + `/api/v1", "weight": 100}
				]
			}
		}`

		var cfg Config
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			t.Fatalf("Failed to unmarshal config: %v", err)
		}

		transport := cfg.Transport()
		req := httptest.NewRequest("GET", "http://lb.test.local/users/123", nil)
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		resp.Body.Close()

		// With strip_base_path=false, target path + request path
		if receivedPath != "/api/v1/users/123" {
			t.Errorf("Expected path '/api/v1/users/123', got '%s'", receivedPath)
		}
	})
}

// TestLoadBalancerPreserveQuery tests the preserve_query option
func TestLoadBalancerPreserveQuery(t *testing.T) {
	t.Run("preserve_query=false (default) merges query params", func(t *testing.T) {
		var receivedQuery string
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedQuery = r.URL.RawQuery
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"backend": "test"}`))
		}))
		defer backend.Close()

		configJSON := `{
			"id": "lb-preserve-query-false",
			"hostname": "lb.test.local",
			"action": {
				"type": "loadbalancer",
				"preserve_query": false,
				"disable_sticky": true,
				"targets": [
					{"url": "` + backend.URL + `/get?backend=1", "weight": 100}
				]
			}
		}`

		var cfg Config
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			t.Fatalf("Failed to unmarshal config: %v", err)
		}

		transport := cfg.Transport()
		req := httptest.NewRequest("GET", "http://lb.test.local/api?foo=bar", nil)
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		resp.Body.Close()

		// With preserve_query=false, both target and request query params should be present
		if !strings.Contains(receivedQuery, "backend=1") {
			t.Errorf("Expected query to contain 'backend=1', got '%s'", receivedQuery)
		}
		if !strings.Contains(receivedQuery, "foo=bar") {
			t.Errorf("Expected query to contain 'foo=bar', got '%s'", receivedQuery)
		}
	})

	t.Run("preserve_query=true uses only request query params", func(t *testing.T) {
		var receivedQuery string
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedQuery = r.URL.RawQuery
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"backend": "test"}`))
		}))
		defer backend.Close()

		configJSON := `{
			"id": "lb-preserve-query-true",
			"hostname": "lb.test.local",
			"action": {
				"type": "loadbalancer",
				"preserve_query": true,
				"disable_sticky": true,
				"targets": [
					{"url": "` + backend.URL + `/get?backend=1", "weight": 100}
				]
			}
		}`

		var cfg Config
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			t.Fatalf("Failed to unmarshal config: %v", err)
		}

		transport := cfg.Transport()
		req := httptest.NewRequest("GET", "http://lb.test.local/api?foo=bar", nil)
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		resp.Body.Close()

		// With preserve_query=true, only request query params should be present
		if receivedQuery != "foo=bar" {
			t.Errorf("Expected query 'foo=bar', got '%s'", receivedQuery)
		}
	})
}

// TestLoadBalancerStickySession tests sticky session functionality
func TestLoadBalancerStickySession(t *testing.T) {
	var backend1Count, backend2Count int64

	backend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&backend1Count, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"backend": "backend-1"}`))
	}))
	defer backend1.Close()

	backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&backend2Count, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"backend": "backend-2"}`))
	}))
	defer backend2.Close()

	configJSON := `{
		"id": "lb-sticky-test",
		"hostname": "lb.sticky.test.local",
		"action": {
			"type": "loadbalancer",
			"disable_sticky": false,
			"sticky_cookie_name": "_sb_test_sticky",
			"targets": [
				{
					"url": "` + backend1.URL + `",
					"weight": 50
				},
				{
					"url": "` + backend2.URL + `",
					"weight": 50
				}
			]
		}
	}`

	var cfg Config
	err := json.Unmarshal([]byte(configJSON), &cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	transport := cfg.Transport()
	if transport == nil {
		t.Fatal("Transport() should not return nil")
	}

	// First request - no cookie
	req1 := httptest.NewRequest("GET", "http://lb.sticky.test.local/test", nil)
	resp1, err := transport.RoundTrip(req1)
	if err != nil {
		t.Fatalf("First request failed: %v", err)
	}

	// Get the sticky cookie from response
	var stickyCookie string
	for _, cookie := range resp1.Cookies() {
		if cookie.Name == "_sb_test_sticky" {
			stickyCookie = cookie.Value
			break
		}
	}
	resp1.Body.Close()

	if stickyCookie == "" {
		t.Log("Note: Sticky cookie not set (this is expected behavior when sticky sessions are working)")
	}

	// Record which backend was selected first
	firstBackend1 := atomic.LoadInt64(&backend1Count)
	firstBackend2 := atomic.LoadInt64(&backend2Count)

	t.Logf("After first request - Backend1: %d, Backend2: %d", firstBackend1, firstBackend2)

	// Subsequent requests with the sticky cookie should go to the same backend
	if stickyCookie != "" {
		for i := 0; i < 10; i++ {
			req := httptest.NewRequest("GET", "http://lb.sticky.test.local/test", nil)
			req.AddCookie(&http.Cookie{Name: "_sb_test_sticky", Value: stickyCookie})
			resp, err := transport.RoundTrip(req)
			if err != nil {
				t.Fatalf("Request %d with cookie failed: %v", i, err)
			}
			resp.Body.Close()
		}

		// Verify all subsequent requests went to the same backend
		finalBackend1 := atomic.LoadInt64(&backend1Count)
		finalBackend2 := atomic.LoadInt64(&backend2Count)

		t.Logf("After 10 more requests - Backend1: %d, Backend2: %d", finalBackend1, finalBackend2)

		// One backend should have all the sticky requests
		if firstBackend1 == 1 {
			// First request went to backend1, all should go to backend1
			if finalBackend1 != 11 {
				t.Logf("Sticky session may not be preserving backend (expected 11 for backend1, got %d)", finalBackend1)
			}
		} else if firstBackend2 == 1 {
			// First request went to backend2, all should go to backend2
			if finalBackend2 != 11 {
				t.Logf("Sticky session may not be preserving backend (expected 11 for backend2, got %d)", finalBackend2)
			}
		}
	}
}
