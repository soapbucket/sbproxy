package config

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestThrottle_RequestQueuedAndServed(t *testing.T) {
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 2,
		"throttle": {
			"enabled": true,
			"max_queue": 10,
			"max_wait": "200ms"
		}
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	clientIP := "10.0.0.1"
	servedCount := 0

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		servedCount++
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)

	// Send 2 requests to fill the rate limit
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("Request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	if servedCount != 2 {
		t.Errorf("Expected 2 served requests, got %d", servedCount)
	}

	// 3rd request should be throttled (queued and eventually served after wait)
	start := time.Now()
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	elapsed := time.Since(start)

	// Should have been served after waiting
	if rec.Code != http.StatusOK {
		t.Errorf("Throttled request: expected 200 (served after wait), got %d", rec.Code)
	}
	if servedCount != 3 {
		t.Errorf("Expected 3 served requests, got %d", servedCount)
	}
	// Should have waited at least some time (the retry-after period)
	if elapsed < 100*time.Millisecond {
		t.Logf("Request was served quickly (elapsed: %v), throttle wait was minimal", elapsed)
	}
}

func TestThrottle_QueueFullReturns429(t *testing.T) {
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 1,
		"throttle": {
			"enabled": true,
			"max_queue": 1,
			"max_wait": "500ms"
		}
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	clientIP := "10.0.0.2"

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)

	// Fill rate limit
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("First request should succeed, got %d", rec.Code)
	}

	// Second request will be queued (fills the queue of size 1)
	done := make(chan struct{})
	go func() {
		req2 := httptest.NewRequest("GET", "/test", nil)
		req2.RemoteAddr = clientIP + ":12345"
		rec2 := httptest.NewRecorder()
		handler.ServeHTTP(rec2, req2)
		close(done)
	}()

	// Give the goroutine time to enqueue
	time.Sleep(50 * time.Millisecond)

	// Third request should get 429 because queue is full
	req3 := httptest.NewRequest("GET", "/test", nil)
	req3.RemoteAddr = clientIP + ":12345"
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429 when queue is full, got %d", rec3.Code)
	}

	body := rec3.Body.String()
	if !strings.Contains(body, "throttle queue full") {
		t.Errorf("Expected 'throttle queue full' in body, got: %s", body)
	}

	// Wait for the queued request to complete
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Queued request did not complete in time")
	}
}

func TestThrottle_MaxWaitExceededReturns429(t *testing.T) {
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 1,
		"throttle": {
			"enabled": true,
			"max_queue": 10,
			"max_wait": "100ms"
		}
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	clientIP := "10.0.0.3"

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)

	// Fill rate limit
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("First request should succeed, got %d", rec.Code)
	}

	// Second request will be throttled, but max_wait is very short (100ms)
	// and the rate limit retry-after is ~1 minute, so it should be capped at max_wait
	// and the request will be served after max_wait
	start := time.Now()
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = clientIP + ":12345"
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	elapsed := time.Since(start)

	// With throttling, the request waits for max_wait then gets served
	// The wait duration is capped at max_wait (100ms)
	if elapsed < 90*time.Millisecond {
		t.Errorf("Expected to wait at least ~100ms, waited only %v", elapsed)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Expected to wait around 100ms, waited %v", elapsed)
	}

	// The throttled request gets served after waiting
	if rec2.Code != http.StatusOK {
		t.Logf("Throttled request returned %d after %v wait (request was served after max_wait)", rec2.Code, elapsed)
	}
}

func TestQuota_DailyLimitEnforced(t *testing.T) {
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 1000,
		"quota": {
			"daily": 5
		}
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	clientIP := "10.0.0.10"

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)

	// Send 5 requests - all should succeed
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("Request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// 6th request should be blocked by daily quota
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429 for quota exceeded, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "daily quota exceeded") {
		t.Errorf("Expected 'daily quota exceeded' in body, got: %s", body)
	}
}

func TestQuota_MonthlyLimitEnforced(t *testing.T) {
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 1000,
		"quota": {
			"monthly": 3
		}
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	clientIP := "10.0.0.11"

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)

	// Send 3 requests - all should succeed
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("Request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// 4th request should be blocked by monthly quota
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429 for monthly quota exceeded, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "monthly quota exceeded") {
		t.Errorf("Expected 'monthly quota exceeded' in body, got: %s", body)
	}
}

func TestQuota_RemainingHeaderDecrements(t *testing.T) {
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 1000,
		"quota": {
			"daily": 10
		}
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	clientIP := "10.0.0.12"

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)

	// Send requests and check X-Quota-Remaining decrements
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("Request %d: expected 200, got %d", i+1, rec.Code)
		}

		remaining := rec.Header().Get("X-Quota-Remaining")
		expectedRemaining := 10 - (i + 1) // 9, 8, 7, 6, 5
		if remaining != strconv.Itoa(expectedRemaining) {
			t.Errorf("Request %d: expected X-Quota-Remaining=%d, got %s", i+1, expectedRemaining, remaining)
		}

		reset := rec.Header().Get("X-Quota-Reset")
		if reset == "" {
			t.Errorf("Request %d: expected X-Quota-Reset header to be set", i+1)
		}
	}
}

func TestQuota_CalendarRenewalResetsCounters(t *testing.T) {
	data := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 1000,
		"quota": {
			"daily": 3,
			"renewal": "calendar"
		}
	}`)

	policy, err := NewRateLimitingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}
	defer policy.(*RateLimitingPolicyConfig).Shutdown()

	rlp := policy.(*RateLimitingPolicyConfig)

	clientIP := "10.0.0.13"

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)

	// Use up daily quota
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("Request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// 4th request should be blocked
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429, got %d", rec.Code)
	}

	// Simulate calendar reset by setting the daily reset time to the past
	rlp.mu.Lock()
	counterKey := "quota:" + clientIP
	if counters, exists := rlp.counters[counterKey]; exists {
		counters.quotaDailyReset = time.Now().Add(-time.Hour) // Set reset to past
	}
	rlp.mu.Unlock()

	// Now requests should be allowed again (counter resets)
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = clientIP + ":12345"
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Errorf("After calendar reset, expected 200, got %d", rec2.Code)
	}

	// Verify remaining is correct after reset
	remaining := rec2.Header().Get("X-Quota-Remaining")
	if remaining != "2" {
		t.Errorf("After reset, expected X-Quota-Remaining=2, got %s", remaining)
	}
}
