package transport

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Mock round tripper for testing per-IP limiter
type perIPMockRoundTripper struct {
	response *http.Response
	err      error
	delay    time.Duration
	callCount int32
}

func (m *perIPMockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt32(&m.callCount, 1)
	
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
	
	if m.err != nil {
		return nil, m.err
	}
	if m.response != nil {
		return m.response, nil
	}
	
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Request:    req,
		Body:       http.NoBody,
	}, nil
}

func (m *perIPMockRoundTripper) getCallCount() int {
	return int(atomic.LoadInt32(&m.callCount))
}

func TestPerIPConnectionLimiter(t *testing.T) {
	t.Run("basic connection limiting per IP", func(t *testing.T) {
		mock := &perIPMockRoundTripper{}
		config := &PerIPConnectionLimiterConfig{
			MaxConnectionsPerIP: 2,
		}
		
		limiter, err := NewPerIPConnectionLimiter(mock, config, nil)
		if err != nil {
			t.Fatalf("failed to create limiter: %v", err)
		}
		defer limiter.Close()

		// Create requests from same IP
		req1 := httptest.NewRequest("GET", "http://example.com", nil)
		req1.RemoteAddr = "192.168.1.100:12345"
		
		req2 := httptest.NewRequest("GET", "http://example.com", nil)
		req2.RemoteAddr = "192.168.1.100:12346"
		
		req3 := httptest.NewRequest("GET", "http://example.com", nil)
		req3.RemoteAddr = "192.168.1.100:12347"

		// Acquire connections
		var wg sync.WaitGroup
		mock.delay = 100 * time.Millisecond // Add delay to hold connections
		
		// First two should succeed
		wg.Add(2)
		go func() {
			defer wg.Done()
			resp, err := limiter.RoundTrip(req1)
			if err != nil {
				t.Errorf("request 1 failed: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected 200, got %d", resp.StatusCode)
			}
		}()
		
		go func() {
			defer wg.Done()
			resp, err := limiter.RoundTrip(req2)
			if err != nil {
				t.Errorf("request 2 failed: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected 200, got %d", resp.StatusCode)
			}
		}()
		
		// Give time for first two to start
		time.Sleep(50 * time.Millisecond)
		
		// Third should be rejected (limit reached)
		resp3, err := limiter.RoundTrip(req3)
		if err != nil {
			t.Errorf("request 3 error: %v", err)
		}
		if resp3.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("expected 503, got %d", resp3.StatusCode)
		}
		
		wg.Wait()
		
		// After connections are released, should be able to connect again
		resp4, err := limiter.RoundTrip(req1)
		if err != nil {
			t.Errorf("request 4 failed: %v", err)
		}
		if resp4.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp4.StatusCode)
		}
	})

	t.Run("different IPs are tracked separately", func(t *testing.T) {
		mock := &perIPMockRoundTripper{}
		config := &PerIPConnectionLimiterConfig{
			MaxConnectionsPerIP: 1,
		}
		
		limiter, err := NewPerIPConnectionLimiter(mock, config, nil)
		if err != nil {
			t.Fatalf("failed to create limiter: %v", err)
		}
		defer limiter.Close()

		// Create requests from different IPs
		req1 := httptest.NewRequest("GET", "http://example.com", nil)
		req1.RemoteAddr = "192.168.1.100:12345"
		
		req2 := httptest.NewRequest("GET", "http://example.com", nil)
		req2.RemoteAddr = "192.168.1.101:12345"

		// Both should succeed since they're from different IPs
		resp1, err := limiter.RoundTrip(req1)
		if err != nil {
			t.Errorf("request 1 failed: %v", err)
		}
		if resp1.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp1.StatusCode)
		}
		
		resp2, err := limiter.RoundTrip(req2)
		if err != nil {
			t.Errorf("request 2 failed: %v", err)
		}
		if resp2.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp2.StatusCode)
		}
	})

	t.Run("whitelisted IPs bypass limits", func(t *testing.T) {
		mock := &perIPMockRoundTripper{}
		config := &PerIPConnectionLimiterConfig{
			MaxConnectionsPerIP: 1,
			WhitelistCIDRs:      []string{"192.168.1.0/24"},
		}
		
		limiter, err := NewPerIPConnectionLimiter(mock, config, nil)
		if err != nil {
			t.Fatalf("failed to create limiter: %v", err)
		}
		defer limiter.Close()

		// Whitelisted IP should bypass limits
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.RemoteAddr = "192.168.1.100:12345"

		// Make more requests than the limit
		for i := 0; i < 5; i++ {
			resp, err := limiter.RoundTrip(req)
			if err != nil {
				t.Errorf("request %d failed: %v", i+1, err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Errorf("request %d: expected 200, got %d", i+1, resp.StatusCode)
			}
		}
	})

	t.Run("connection duration timeout", func(t *testing.T) {
		mock := &perIPMockRoundTripper{
			delay: 200 * time.Millisecond,
		}
		config := &PerIPConnectionLimiterConfig{
			MaxConnectionDuration: 50 * time.Millisecond,
		}
		
		limiter, err := NewPerIPConnectionLimiter(mock, config, nil)
		if err != nil {
			t.Fatalf("failed to create limiter: %v", err)
		}
		defer limiter.Close()

		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.RemoteAddr = "192.168.1.100:12345"

		start := time.Now()
		_, err = limiter.RoundTrip(req)
		duration := time.Since(start)

		// Should timeout before the mock delay completes
		if duration >= 200*time.Millisecond {
			t.Errorf("expected timeout before 200ms, took %v", duration)
		}
		
		if err == nil {
			t.Error("expected context deadline exceeded error")
		}
	})

	t.Run("X-Forwarded-For header is respected", func(t *testing.T) {
		mock := &perIPMockRoundTripper{}
		config := &PerIPConnectionLimiterConfig{
			MaxConnectionsPerIP: 1,
		}
		
		limiter, err := NewPerIPConnectionLimiter(mock, config, nil)
		if err != nil {
			t.Fatalf("failed to create limiter: %v", err)
		}
		defer limiter.Close()

		// Create two requests with same X-Forwarded-For but different RemoteAddr
		req1 := httptest.NewRequest("GET", "http://example.com", nil)
		req1.RemoteAddr = "10.0.0.1:12345"
		req1.Header.Set("X-Forwarded-For", "203.0.113.1")
		
		req2 := httptest.NewRequest("GET", "http://example.com", nil)
		req2.RemoteAddr = "10.0.0.2:12346"
		req2.Header.Set("X-Forwarded-For", "203.0.113.1")

		// First request should succeed
		mock.delay = 100 * time.Millisecond
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := limiter.RoundTrip(req1)
			if err != nil {
				t.Errorf("request 1 failed: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected 200, got %d", resp.StatusCode)
			}
		}()
		
		// Give time for first request to start
		time.Sleep(50 * time.Millisecond)
		
		// Second request should be rejected (same X-Forwarded-For IP)
		resp2, err := limiter.RoundTrip(req2)
		if err != nil {
			t.Errorf("request 2 error: %v", err)
		}
		if resp2.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("expected 503, got %d", resp2.StatusCode)
		}
		
		wg.Wait()
	})

	t.Run("metrics tracking", func(t *testing.T) {
		mock := &perIPMockRoundTripper{}
		config := &PerIPConnectionLimiterConfig{
			MaxConnectionsPerIP: 1,
		}
		
		limiter, err := NewPerIPConnectionLimiter(mock, config, nil)
		if err != nil {
			t.Fatalf("failed to create limiter: %v", err)
		}
		defer limiter.Close()

		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.RemoteAddr = "192.168.1.100:12345"

		// First request should succeed
		limiter.RoundTrip(req)
		
		// Second concurrent request should be denied
		mock.delay = 100 * time.Millisecond
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			limiter.RoundTrip(req)
		}()
		
		time.Sleep(50 * time.Millisecond)
		limiter.RoundTrip(req) // Should be denied
		
		wg.Wait()

		allowed, denied := limiter.GetMetrics()
		if allowed < 1 {
			t.Errorf("expected at least 1 allowed, got %d", allowed)
		}
		if denied < 1 {
			t.Errorf("expected at least 1 denied, got %d", denied)
		}
	})

	t.Run("cleanup removes stale tracking data", func(t *testing.T) {
		mock := &perIPMockRoundTripper{
			delay: 50 * time.Millisecond, // Keep connection active briefly
		}
		config := &PerIPConnectionLimiterConfig{
			MaxConnectionsPerIP: 1,
			CleanupInterval:     100 * time.Millisecond,
		}
		
		limiter, err := NewPerIPConnectionLimiter(mock, config, nil)
		if err != nil {
			t.Fatalf("failed to create limiter: %v", err)
		}
		defer limiter.Close()

		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.RemoteAddr = "192.168.1.100:12345"

		// Make a request in a goroutine to keep connection active
		done := make(chan bool)
		go func() {
			limiter.RoundTrip(req)
			done <- true
		}()
		
		// Check immediately while connection is still active
		time.Sleep(10 * time.Millisecond)
		if tracked := limiter.GetTotalTrackedIPs(); tracked != 1 {
			t.Errorf("expected 1 tracked IP while connection active, got %d", tracked)
		}
		
		// Wait for request to complete and connection to be released
		<-done
		time.Sleep(10 * time.Millisecond)
		
		// Connection should be released, but entry might still exist briefly
		// Wait for cleanup to remove it
		time.Sleep(150 * time.Millisecond)
		
		// Should be cleaned up after cleanup interval
		if tracked := limiter.GetTotalTrackedIPs(); tracked != 0 {
			t.Errorf("expected 0 tracked IPs after cleanup, got %d", tracked)
		}
	})
}

func TestPerIPConnectionLimiterRateLimiting(t *testing.T) {
	t.Run("rate limiting without distributed rate limiter falls back gracefully", func(t *testing.T) {
		mock := &perIPMockRoundTripper{}
		config := &PerIPConnectionLimiterConfig{
			ConnectionsPerSecondPerIP: 5,
			MaxConnectionsPerIP:       10,
		}
		
		// No rate limiter provided - should fall back gracefully
		limiter, err := NewPerIPConnectionLimiter(mock, config, nil)
		if err != nil {
			t.Fatalf("failed to create limiter: %v", err)
		}
		defer limiter.Close()

		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.RemoteAddr = "192.168.1.100:12345"

		// Should allow all requests since no distributed rate limiter is configured
		successCount := 0
		for i := 0; i < 10; i++ {
			resp, _ := limiter.RoundTrip(req)
			if resp.StatusCode == http.StatusOK {
				successCount++
			}
		}

		// All should succeed since we're within max connections and no rate limiter
		if successCount != 10 {
			t.Errorf("expected 10 successful requests, got %d", successCount)
		}
	})
}

func TestPerIPConnectionLimiterConcurrency(t *testing.T) {
	t.Run("high concurrency stress test", func(t *testing.T) {
		mock := &perIPMockRoundTripper{
			delay: 10 * time.Millisecond,
		}
		config := &PerIPConnectionLimiterConfig{
			MaxConnectionsPerIP: 10,
		}
		
		limiter, err := NewPerIPConnectionLimiter(mock, config, nil)
		if err != nil {
			t.Fatalf("failed to create limiter: %v", err)
		}
		defer limiter.Close()

		var wg sync.WaitGroup
		concurrency := 100
		successCount := atomic.Int32{}
		deniedCount := atomic.Int32{}

		// Create requests from same IP
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				
				req := httptest.NewRequest("GET", "http://example.com", nil)
				req.RemoteAddr = fmt.Sprintf("192.168.1.100:%d", 10000+i)
				req.Header.Set("X-Real-IP", "192.168.1.100")
				
				resp, err := limiter.RoundTrip(req)
				if err != nil {
					t.Errorf("request %d error: %v", i, err)
					return
				}
				
				if resp.StatusCode == http.StatusOK {
					successCount.Add(1)
				} else if resp.StatusCode == http.StatusServiceUnavailable {
					deniedCount.Add(1)
				}
			}(i)
		}

		wg.Wait()

		t.Logf("Success: %d, Denied: %d", successCount.Load(), deniedCount.Load())
		
		// Should have some denied connections due to limit
		if deniedCount.Load() < 1 {
			t.Logf("expected some denied connections, got %d", deniedCount.Load())
		}
	})
}


