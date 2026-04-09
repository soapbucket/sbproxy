package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestRateLimitingPolicy_Basic(t *testing.T) {
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 10,
		"requests_per_hour": 100
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create rate limiting policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	clientIP := "192.168.1.100"

	// Send requests up to limit
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := policy.Apply(next)
		handler.ServeHTTP(rec, req)

		if !nextCalled {
			t.Errorf("Request %d should have been allowed", i+1)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("Request %d: expected status %d, got %d", i+1, http.StatusOK, rec.Code)
		}
	}

	// 11th request should be blocked
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec := httptest.NewRecorder()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("Request 11 should have been blocked")
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status %d, got %d", http.StatusTooManyRequests, rec.Code)
	}
}

func TestRateLimitingPolicy_PerEndpointExactMatch(t *testing.T) {
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 100,
		"endpoint_limits": {
			"/api/auth/login": {
				"requests_per_minute": 5
			},
			"/api/payment": {
				"requests_per_minute": 10
			}
		}
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create rate limiting policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	clientIP := "192.168.1.100"

	// Test /api/auth/login endpoint - should limit to 5 requests per minute
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("POST", "/api/auth/login", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := policy.Apply(next)
		handler.ServeHTTP(rec, req)

		if !nextCalled {
			t.Errorf("Request %d to /api/auth/login should have been allowed", i+1)
		}
	}

	// 6th request to /api/auth/login should be blocked
	req := httptest.NewRequest("POST", "/api/auth/login", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec := httptest.NewRecorder()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("Request 6 to /api/auth/login should have been blocked")
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status %d, got %d", http.StatusTooManyRequests, rec.Code)
	}

	// Error message should include endpoint
	body := rec.Body.String()
	if !strings.Contains(body, "/api/auth/login") {
		t.Error("Error message should include endpoint path")
	}

	// Test /api/payment endpoint - should limit to 10 requests per minute
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("POST", "/api/payment", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := policy.Apply(next)
		handler.ServeHTTP(rec, req)

		if !nextCalled {
			t.Errorf("Request %d to /api/payment should have been allowed", i+1)
		}
	}

	// 11th request to /api/payment should be blocked
	req = httptest.NewRequest("POST", "/api/payment", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec = httptest.NewRecorder()

	nextCalled = false
	next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler = policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("Request 11 to /api/payment should have been blocked")
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status %d, got %d", http.StatusTooManyRequests, rec.Code)
	}
}

func TestRateLimitingPolicy_PerEndpointPrefixMatch(t *testing.T) {
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 100,
		"endpoint_limits": {
			"/api/": {
				"requests_per_minute": 50
			},
			"/api/auth/": {
				"requests_per_minute": 20
			},
			"/admin/": {
				"requests_per_minute": 10
			}
		}
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create rate limiting policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	clientIP := "192.168.1.100"

	// Test /api/users endpoint - should match /api/ prefix (50 requests/min)
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest("GET", "/api/users", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := policy.Apply(next)
		handler.ServeHTTP(rec, req)

		if !nextCalled {
			t.Errorf("Request %d to /api/users should have been allowed", i+1)
		}
	}

	// 51st request should be blocked
	req := httptest.NewRequest("GET", "/api/users", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec := httptest.NewRecorder()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("Request 51 to /api/users should have been blocked")
	}

	// Test /api/auth/login - should match /api/auth/ prefix (20 requests/min, longest match)
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest("POST", "/api/auth/login", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := policy.Apply(next)
		handler.ServeHTTP(rec, req)

		if !nextCalled {
			t.Errorf("Request %d to /api/auth/login should have been allowed", i+1)
		}
	}

	// 21st request should be blocked (using /api/auth/ limit, not /api/ limit)
	req = httptest.NewRequest("POST", "/api/auth/login", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec = httptest.NewRecorder()

	nextCalled = false
	next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler = policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("Request 21 to /api/auth/login should have been blocked (using /api/auth/ limit)")
	}
}

func TestRateLimitingPolicy_PerEndpointDifferentIPs(t *testing.T) {
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 100,
		"endpoint_limits": {
			"/api/auth/login": {
				"requests_per_minute": 5
			}
		}
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create rate limiting policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	// Different IPs should have separate counters
	clientIP1 := "192.168.1.100"
	clientIP2 := "192.168.1.101"

	// IP1: Send 5 requests (should all pass)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("POST", "/api/auth/login", nil)
		req.RemoteAddr = clientIP1 + ":12345"
		rec := httptest.NewRecorder()

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := policy.Apply(next)
		handler.ServeHTTP(rec, req)

		if !nextCalled {
			t.Errorf("IP1 Request %d should have been allowed", i+1)
		}
	}

	// IP1: 6th request should be blocked
	req := httptest.NewRequest("POST", "/api/auth/login", nil)
	req.RemoteAddr = clientIP1 + ":12345"
	rec := httptest.NewRecorder()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("IP1 Request 6 should have been blocked")
	}

	// IP2: Should be able to send 5 requests (separate counter)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("POST", "/api/auth/login", nil)
		req.RemoteAddr = clientIP2 + ":12345"
		rec := httptest.NewRecorder()

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := policy.Apply(next)
		handler.ServeHTTP(rec, req)

		if !nextCalled {
			t.Errorf("IP2 Request %d should have been allowed", i+1)
		}
	}

	// IP2: 6th request should be blocked
	req = httptest.NewRequest("POST", "/api/auth/login", nil)
	req.RemoteAddr = clientIP2 + ":12345"
	rec = httptest.NewRecorder()

	nextCalled = false
	next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler = policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("IP2 Request 6 should have been blocked")
	}
}

func TestRateLimitingPolicy_PerEndpointDifferentEndpoints(t *testing.T) {
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 100,
		"endpoint_limits": {
			"/api/auth/login": {
				"requests_per_minute": 5
			},
			"/api/payment": {
				"requests_per_minute": 10
			}
		}
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create rate limiting policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	clientIP := "192.168.1.100"

	// Exhaust limit for /api/auth/login
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("POST", "/api/auth/login", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := policy.Apply(next)
		handler.ServeHTTP(rec, req)
	}

	// /api/auth/login should now be blocked
	req := httptest.NewRequest("POST", "/api/auth/login", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec := httptest.NewRecorder()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("/api/auth/login should be blocked after 5 requests")
	}

	// /api/payment should still work (different endpoint, separate counter)
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("POST", "/api/payment", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := policy.Apply(next)
		handler.ServeHTTP(rec, req)

		if !nextCalled {
			t.Errorf("/api/payment request %d should have been allowed", i+1)
		}
	}
}

func TestRateLimitingPolicy_MergeIPAndEndpointLimits(t *testing.T) {
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 100,
		"custom_limits": {
			"192.168.1.100": {
				"requests_per_minute": 50
			}
		},
		"endpoint_limits": {
			"/api/auth/login": {
				"requests_per_minute": 20
			}
		}
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create rate limiting policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	clientIP := "192.168.1.100"

	// IP limit is 50, endpoint limit is 20, so effective limit should be 20 (more restrictive)
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest("POST", "/api/auth/login", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := policy.Apply(next)
		handler.ServeHTTP(rec, req)

		if !nextCalled {
			t.Errorf("Request %d should have been allowed (effective limit is 20)", i+1)
		}
	}

	// 21st request should be blocked (using the more restrictive limit of 20)
	req := httptest.NewRequest("POST", "/api/auth/login", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec := httptest.NewRecorder()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("Request 21 should have been blocked (effective limit is 20, not 50)")
	}
}

func TestRateLimitingPolicy_BackwardCompatibility(t *testing.T) {
	// Test without endpoint_limits (backward compatibility)
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 10,
		"requests_per_hour": 100
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create rate limiting policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	ratePolicy := policy.(*RateLimitingPolicyConfig)
	if len(ratePolicy.EndpointLimits) > 0 {
		t.Error("EndpointLimits should be empty when not configured")
	}

	clientIP := "192.168.1.100"

	// Should work as before (IP-based only)
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/any/endpoint", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := policy.Apply(next)
		handler.ServeHTTP(rec, req)

		if !nextCalled {
			t.Errorf("Request %d should have been allowed", i+1)
		}
	}

	// 11th request should be blocked
	req := httptest.NewRequest("GET", "/any/endpoint", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec := httptest.NewRecorder()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("Request 11 should have been blocked")
	}
}

func TestRateLimitingPolicy_EmptyPath(t *testing.T) {
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 10,
		"endpoint_limits": {
			"/": {
				"requests_per_minute": 5
			}
		}
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create rate limiting policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	clientIP := "192.168.1.100"

	// Test empty path (should be normalized to "/")
	// httptest.NewRequest doesn't accept empty URL, so we'll manually set it
	req := httptest.NewRequest("GET", "/", nil)
	req.URL.Path = "" // Manually set to empty to test normalization
	req.RemoteAddr = clientIP + ":12345"
	rec := httptest.NewRecorder()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("Empty path request should have been allowed")
	}
}

func TestRateLimitingPolicy_GetLimitsForRequest(t *testing.T) {
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 100,
		"requests_per_hour": 1000,
		"custom_limits": {
			"192.168.1.100": {
				"requests_per_minute": 50,
				"requests_per_hour": 500
			}
		},
		"endpoint_limits": {
			"/api/auth/login": {
				"requests_per_minute": 5,
				"requests_per_hour": 20
			},
			"/api/": {
				"requests_per_minute": 30
			}
		}
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create rate limiting policy: %v", err)
	}

	ratePolicy := policy.(*RateLimitingPolicyConfig)

	// Test exact match
	limits, pattern := ratePolicy.getLimitsForRequest("192.168.1.100", "/api/auth/login")
	if limits.RequestsPerMinute != 5 {
		t.Errorf("Expected 5 requests/min for /api/auth/login, got %d", limits.RequestsPerMinute)
	}
	if pattern != "/api/auth/login" {
		t.Errorf("Expected pattern /api/auth/login, got %s", pattern)
	}

	// Test prefix match (longest)
	limits, pattern = ratePolicy.getLimitsForRequest("192.168.1.100", "/api/auth/register")
	if limits.RequestsPerMinute != 30 {
		t.Errorf("Expected 30 requests/min for /api/auth/register (matches /api/), got %d", limits.RequestsPerMinute)
	}
	if pattern != "/api/" {
		t.Errorf("Expected pattern /api/, got %s", pattern)
	}

	// Test no endpoint match (should use IP limits)
	limits, pattern = ratePolicy.getLimitsForRequest("192.168.1.100", "/other/endpoint")
	if limits.RequestsPerMinute != 50 {
		t.Errorf("Expected 50 requests/min (IP limit), got %d", limits.RequestsPerMinute)
	}
	if pattern != "/other/endpoint" {
		t.Errorf("Expected pattern /other/endpoint, got %s", pattern)
	}

	// Test different IP (should use default limits)
	limits, _ = ratePolicy.getLimitsForRequest("192.168.1.200", "/api/auth/login")
	if limits.RequestsPerMinute != 5 {
		t.Errorf("Expected 5 requests/min (endpoint limit), got %d", limits.RequestsPerMinute)
	}
}

func TestRateLimitingPolicy_MinNonZero(t *testing.T) {
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 100
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create rate limiting policy: %v", err)
	}

	ratePolicy := policy.(*RateLimitingPolicyConfig)

	// Test minNonZero function
	if ratePolicy.minNonZero(0, 10) != 10 {
		t.Error("minNonZero(0, 10) should return 10")
	}
	if ratePolicy.minNonZero(10, 0) != 10 {
		t.Error("minNonZero(10, 0) should return 10")
	}
	if ratePolicy.minNonZero(5, 10) != 5 {
		t.Error("minNonZero(5, 10) should return 5")
	}
	if ratePolicy.minNonZero(10, 5) != 5 {
		t.Error("minNonZero(10, 5) should return 5")
	}
	if ratePolicy.minNonZero(0, 0) != 0 {
		t.Error("minNonZero(0, 0) should return 0")
	}
}

func TestRateLimitingPolicy_GetCounterKey(t *testing.T) {
	// Test with endpoint limits
	data1 := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 100,
		"endpoint_limits": {
			"/api/": {
				"requests_per_minute": 50
			}
		}
	}`)

	policy1, err := NewRateLimitingPolicy(data1)
	if err != nil {
		t.Fatalf("Failed to create rate limiting policy: %v", err)
	}

	ratePolicy1 := policy1.(*RateLimitingPolicyConfig)
	key1 := ratePolicy1.getCounterKey("192.168.1.100", "/api/users")
	expected1 := "192.168.1.100:/api/users"
	if key1 != expected1 {
		t.Errorf("Expected counter key %s, got %s", expected1, key1)
	}

	// Test without endpoint limits (backward compatibility)
	data2 := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 100
	}`)

	policy2, err := NewRateLimitingPolicy(data2)
	if err != nil {
		t.Fatalf("Failed to create rate limiting policy: %v", err)
	}

	ratePolicy2 := policy2.(*RateLimitingPolicyConfig)
	key2 := ratePolicy2.getCounterKey("192.168.1.100", "/api/users")
	expected2 := "192.168.1.100"
	if key2 != expected2 {
		t.Errorf("Expected counter key %s, got %s", expected2, key2)
	}
}

func TestRateLimitingPolicy_Whitelist(t *testing.T) {
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 10,
		"whitelist": ["192.168.1.100"]
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create rate limiting policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	// Whitelisted IP should bypass rate limiting
	whitelistedIP := "192.168.1.100"
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = whitelistedIP + ":12345"
		rec := httptest.NewRecorder()

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := policy.Apply(next)
		handler.ServeHTTP(rec, req)

		if !nextCalled {
			t.Errorf("Request %d from whitelisted IP should have been allowed", i+1)
		}
	}
}

func TestRateLimitingPolicy_Blacklist(t *testing.T) {
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 100,
		"blacklist": ["192.168.1.100"]
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create rate limiting policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	// Blacklisted IP should be blocked immediately
	blacklistedIP := "192.168.1.100"
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = blacklistedIP + ":12345"
	rec := httptest.NewRecorder()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("Request from blacklisted IP should have been blocked")
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status %d, got %d", http.StatusTooManyRequests, rec.Code)
	}
}

func TestRateLimitingPolicy_Disabled(t *testing.T) {
	data := []byte(`{
		"type": "rate_limiting",
		"disabled": true,
		"requests_per_minute": 10
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create rate limiting policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	clientIP := "192.168.1.100"

	// Disabled policy should allow all requests
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := policy.Apply(next)
		handler.ServeHTTP(rec, req)

		if !nextCalled {
			t.Errorf("Request %d should have been allowed (policy disabled)", i+1)
		}
	}
}

func TestRateLimitingPolicy_NoIP(t *testing.T) {
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 10
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create rate limiting policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	// Request without IP should be allowed (can't rate limit without IP)
	req := httptest.NewRequest("GET", "/test", nil)
	// Don't set RemoteAddr
	rec := httptest.NewRecorder()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("Request without IP should have been allowed")
	}
}

func TestRateLimitingPolicy_JSONUnmarshal(t *testing.T) {
	jsonStr := `{
		"type": "rate_limiting",
		"requests_per_minute": 100,
		"requests_per_hour": 5000,
		"requests_per_day": 50000,
		"endpoint_limits": {
			"/api/auth/login": {
				"requests_per_minute": 5,
				"requests_per_hour": 20,
				"requests_per_day": 100
			},
			"/api/": {
				"requests_per_minute": 50
			}
		}
	}`

	var policy RateLimitingPolicy
	if err := json.Unmarshal([]byte(jsonStr), &policy); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if policy.RequestsPerMinute != 100 {
		t.Errorf("Expected RequestsPerMinute 100, got %d", policy.RequestsPerMinute)
	}

	if policy.EndpointLimits == nil {
		t.Fatal("EndpointLimits should not be nil")
	}

	loginLimit, exists := policy.EndpointLimits["/api/auth/login"]
	if !exists {
		t.Fatal("Endpoint limit for /api/auth/login should exist")
	}
	if loginLimit.RequestsPerMinute != 5 {
		t.Errorf("Expected 5 requests/min for /api/auth/login, got %d", loginLimit.RequestsPerMinute)
	}
	if loginLimit.RequestsPerHour != 20 {
		t.Errorf("Expected 20 requests/hour for /api/auth/login, got %d", loginLimit.RequestsPerHour)
	}
	if loginLimit.RequestsPerDay != 100 {
		t.Errorf("Expected 100 requests/day for /api/auth/login, got %d", loginLimit.RequestsPerDay)
	}

	apiLimit, exists := policy.EndpointLimits["/api/"]
	if !exists {
		t.Fatal("Endpoint limit for /api/ should exist")
	}
	if apiLimit.RequestsPerMinute != 50 {
		t.Errorf("Expected 50 requests/min for /api/, got %d", apiLimit.RequestsPerMinute)
	}
}

func TestRateLimitingPolicy_Headers(t *testing.T) {
	// Test with headers enabled (default all headers)
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 10,
		"headers": {
			"enabled": true
		}
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create rate limiting policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	clientIP := "192.168.1.100"

	// First request should include rate limit headers
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	// Check for rate limit headers (IETF draft-polli-ratelimit-headers-02 with X- prefix)
	if rec.Header().Get("X-RateLimit-Limit") != "10" {
		t.Errorf("Expected X-RateLimit-Limit header to be '10', got '%s'", rec.Header().Get("X-RateLimit-Limit"))
	}
	if rec.Header().Get("X-RateLimit-Remaining") != "9" {
		t.Errorf("Expected X-RateLimit-Remaining header to be '9', got '%s'", rec.Header().Get("X-RateLimit-Remaining"))
	}
	if rec.Header().Get("X-RateLimit-Reset") == "" {
		t.Error("Expected X-RateLimit-Reset header to be set")
	}
	if rec.Header().Get("X-RateLimit-Used") != "1" {
		t.Errorf("Expected X-RateLimit-Used header to be '1', got '%s'", rec.Header().Get("X-RateLimit-Used"))
	}
}

func TestRateLimitingPolicy_HeadersSelectiveInclude(t *testing.T) {
	// Test with only specific headers enabled
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 10,
		"headers": {
			"enabled": true,
			"include_limit": true,
			"include_remaining": true,
			"include_reset": false,
			"include_used": false
		}
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create rate limiting policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	clientIP := "192.168.1.101"

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	// Check that only selected headers are present
	if rec.Header().Get("X-RateLimit-Limit") != "10" {
		t.Errorf("Expected X-RateLimit-Limit header to be '10', got '%s'", rec.Header().Get("X-RateLimit-Limit"))
	}
	if rec.Header().Get("X-RateLimit-Remaining") != "9" {
		t.Errorf("Expected X-RateLimit-Remaining header to be '9', got '%s'", rec.Header().Get("X-RateLimit-Remaining"))
	}
	if rec.Header().Get("X-RateLimit-Reset") != "" {
		t.Error("Expected X-RateLimit-Reset header to NOT be set")
	}
	if rec.Header().Get("X-RateLimit-Used") != "" {
		t.Error("Expected X-RateLimit-Used header to NOT be set")
	}
}

func TestRateLimitingPolicy_HeadersCustomPrefix(t *testing.T) {
	// Test with custom header prefix
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 10,
		"headers": {
			"enabled": true,
			"header_prefix": "X-MyApp-RateLimit"
		}
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create rate limiting policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	clientIP := "192.168.1.102"

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	// Check for custom prefix headers
	if rec.Header().Get("X-MyApp-RateLimit-Limit") != "10" {
		t.Errorf("Expected X-MyApp-RateLimit-Limit header to be '10', got '%s'", rec.Header().Get("X-MyApp-RateLimit-Limit"))
	}
	if rec.Header().Get("X-MyApp-RateLimit-Remaining") != "9" {
		t.Errorf("Expected X-MyApp-RateLimit-Remaining header to be '9', got '%s'", rec.Header().Get("X-MyApp-RateLimit-Remaining"))
	}
	// Standard prefix should NOT be present
	if rec.Header().Get("X-RateLimit-Limit") != "" {
		t.Error("Expected X-RateLimit-Limit header to NOT be set when using custom prefix")
	}
}

func TestRateLimitingPolicy_HeadersOnRateLimitExceeded(t *testing.T) {
	// Test headers when rate limit is exceeded
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 3,
		"headers": {
			"enabled": true,
			"include_retry_after": true
		}
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create rate limiting policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	clientIP := "192.168.1.103"

	// Exhaust the rate limit
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := policy.Apply(next)
		handler.ServeHTTP(rec, req)
	}

	// 4th request should be rate limited with headers
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status %d, got %d", http.StatusTooManyRequests, rec.Code)
	}

	// Check rate limit headers on exceeded response
	if rec.Header().Get("X-RateLimit-Limit") != "3" {
		t.Errorf("Expected X-RateLimit-Limit header to be '3', got '%s'", rec.Header().Get("X-RateLimit-Limit"))
	}
	if rec.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Errorf("Expected X-RateLimit-Remaining header to be '0', got '%s'", rec.Header().Get("X-RateLimit-Remaining"))
	}
}

func TestRateLimitingPolicy_HeadersDisabled(t *testing.T) {
	// Test with headers disabled (default)
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 10
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create rate limiting policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	clientIP := "192.168.1.104"

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	// No rate limit headers should be present when disabled
	if rec.Header().Get("X-RateLimit-Limit") != "" {
		t.Error("Expected X-RateLimit-Limit header to NOT be set when headers disabled")
	}
	if rec.Header().Get("X-RateLimit-Remaining") != "" {
		t.Error("Expected X-RateLimit-Remaining header to NOT be set when headers disabled")
	}
	if rec.Header().Get("X-RateLimit-Reset") != "" {
		t.Error("Expected X-RateLimit-Reset header to NOT be set when headers disabled")
	}
}

func TestRateLimitingPolicy_HeadersConfigJSONUnmarshal(t *testing.T) {
	jsonStr := `{
		"type": "rate_limiting",
		"requests_per_minute": 100,
		"headers": {
			"enabled": true,
			"include_retry_after": true,
			"include_limit": true,
			"include_remaining": true,
			"include_reset": true,
			"include_used": false,
			"reset_format": "unix_timestamp",
			"header_prefix": "X-Custom-RateLimit"
		}
	}`

	var policy RateLimitingPolicy
	if err := json.Unmarshal([]byte(jsonStr), &policy); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if !policy.Headers.Enabled {
		t.Error("Expected Headers.Enabled to be true")
	}
	if !policy.Headers.IncludeRetryAfter {
		t.Error("Expected Headers.IncludeRetryAfter to be true")
	}
	if !policy.Headers.IncludeLimit {
		t.Error("Expected Headers.IncludeLimit to be true")
	}
	if !policy.Headers.IncludeRemaining {
		t.Error("Expected Headers.IncludeRemaining to be true")
	}
	if !policy.Headers.IncludeReset {
		t.Error("Expected Headers.IncludeReset to be true")
	}
	if policy.Headers.IncludeUsed {
		t.Error("Expected Headers.IncludeUsed to be false")
	}
	if policy.Headers.ResetFormat != "unix_timestamp" {
		t.Errorf("Expected Headers.ResetFormat to be 'unix_timestamp', got '%s'", policy.Headers.ResetFormat)
	}
	if policy.Headers.HeaderPrefix != "X-Custom-RateLimit" {
		t.Errorf("Expected Headers.HeaderPrefix to be 'X-Custom-RateLimit', got '%s'", policy.Headers.HeaderPrefix)
	}
}

// TestRateLimitingPolicy_DemoSecurityScenario tests the exact scenario from docs/demo/04_SECURITY.md
// Expected: First 60 requests get 200, requests 61+ get 429 with proper headers
func TestRateLimitingPolicy_DemoSecurityScenario(t *testing.T) {
	// This matches the demo config in conf/demo.hosts.json for secure.demo.soapbucket.com
	data := []byte(`{
		"type": "rate_limiting",
		"algorithm": "sliding_window",
		"requests_per_minute": 60,
		"requests_per_hour": 1000,
		"burst_size": 10,
		"whitelist": ["10.0.0.0/8", "172.16.0.0/12"],
		"blacklist": [],
		"headers": {
			"enabled": true,
			"include_retry_after": true,
			"include_remaining": true,
			"include_limit": true,
			"include_reset": true
		}
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create rate limiting policy: %v", err)
	}

	cfg := &Config{ID: "secure-demo"}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	// Use an IP that is NOT whitelisted (not in 10.0.0.0/8 or 172.16.0.0/12)
	clientIP := "203.0.113.1" // TEST-NET-3, not in any whitelist

	// Send 60 requests - all should succeed with proper headers
	for i := 1; i <= 60; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := policy.Apply(next)
		handler.ServeHTTP(rec, req)

		if !nextCalled {
			t.Errorf("Request %d should have been allowed (within 60 limit)", i)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("Request %d: expected status 200, got %d", i, rec.Code)
		}

		// Verify headers on successful requests
		limitHeader := rec.Header().Get("X-RateLimit-Limit")
		if limitHeader != "60" {
			t.Errorf("Request %d: expected X-RateLimit-Limit '60', got '%s'", i, limitHeader)
		}

		remainingHeader := rec.Header().Get("X-RateLimit-Remaining")
		expectedRemaining := 60 - i
		if remainingHeader != strconv.Itoa(expectedRemaining) {
			t.Errorf("Request %d: expected X-RateLimit-Remaining '%d', got '%s'", i, expectedRemaining, remainingHeader)
		}

		resetHeader := rec.Header().Get("X-RateLimit-Reset")
		if resetHeader == "" {
			t.Errorf("Request %d: expected X-RateLimit-Reset to be set", i)
		}
	}

	// Send 40 more requests - all should be rate limited (429)
	for i := 61; i <= 100; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := policy.Apply(next)
		handler.ServeHTTP(rec, req)

		if nextCalled {
			t.Errorf("Request %d should have been blocked (over 60 limit)", i)
		}
		if rec.Code != http.StatusTooManyRequests {
			t.Errorf("Request %d: expected status 429, got %d", i, rec.Code)
		}

		// Verify headers on rate-limited responses
		limitHeader := rec.Header().Get("X-RateLimit-Limit")
		if limitHeader != "60" {
			t.Errorf("Request %d: expected X-RateLimit-Limit '60', got '%s'", i, limitHeader)
		}

		remainingHeader := rec.Header().Get("X-RateLimit-Remaining")
		if remainingHeader != "0" {
			t.Errorf("Request %d: expected X-RateLimit-Remaining '0', got '%s'", i, remainingHeader)
		}

		resetHeader := rec.Header().Get("X-RateLimit-Reset")
		if resetHeader == "" {
			t.Errorf("Request %d: expected X-RateLimit-Reset to be set", i)
		}
	}
}

// TestRateLimitingPolicy_RetryAfterHeader specifically tests that Retry-After header is set on 429 responses
func TestRateLimitingPolicy_RetryAfterHeader(t *testing.T) {
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 5,
		"headers": {
			"enabled": true,
			"include_retry_after": true
		}
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create rate limiting policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	clientIP := "203.0.113.50"

	// Exhaust the rate limit
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := policy.Apply(next)
		handler.ServeHTTP(rec, req)
	}

	// 6th request should be rate limited with Retry-After header
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", rec.Code)
	}

	// Verify Retry-After header is set and is a positive integer
	retryAfter := rec.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Error("Expected Retry-After header to be set on 429 response")
	} else {
		retrySeconds, err := strconv.Atoi(retryAfter)
		if err != nil {
			t.Errorf("Retry-After header should be an integer, got '%s'", retryAfter)
		} else if retrySeconds <= 0 || retrySeconds > 60 {
			t.Errorf("Retry-After should be between 1-60 seconds, got %d", retrySeconds)
		}
	}
}

// TestRateLimitingPolicy_WhitelistBypassNoHeaders verifies whitelisted IPs bypass rate limiting
// and don't receive rate limit headers (expected behavior for whitelisted clients)
func TestRateLimitingPolicy_WhitelistBypassNoHeaders(t *testing.T) {
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 5,
		"whitelist": ["192.168.1.0/24"],
		"headers": {
			"enabled": true,
			"include_limit": true,
			"include_remaining": true
		}
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create rate limiting policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	// Whitelisted IP (in 192.168.1.0/24)
	whitelistedIP := "192.168.1.100"

	// Send 20 requests - all should pass without rate limit headers
	for i := 1; i <= 20; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = whitelistedIP + ":12345"
		rec := httptest.NewRecorder()

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := policy.Apply(next)
		handler.ServeHTTP(rec, req)

		if !nextCalled {
			t.Errorf("Request %d from whitelisted IP should have been allowed", i)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("Request %d: expected status 200, got %d", i, rec.Code)
		}

		// Whitelisted IPs should NOT receive rate limit headers (they bypass the check entirely)
		if rec.Header().Get("X-RateLimit-Limit") != "" {
			t.Errorf("Request %d: whitelisted IP should NOT receive X-RateLimit-Limit header", i)
		}
		if rec.Header().Get("X-RateLimit-Remaining") != "" {
			t.Errorf("Request %d: whitelisted IP should NOT receive X-RateLimit-Remaining header", i)
		}
	}
}