package transport

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Mock transport that always succeeds
type mockTransport struct {
	callCount int32
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt32(&m.callCount, 1)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       http.NoBody,
		Request:    req,
	}, nil
}

func TestNewRateLimiter(t *testing.T) {
	mockTr := &mockTransport{}
	rl := NewRateLimiter(mockTr, 10, 20)

	if rl == nil {
		t.Fatal("NewRateLimiter returned nil")
	}

	limiter, ok := rl.(*RateLimiter)
	if !ok {
		t.Fatal("NewRateLimiter did not return *RateLimiter")
	}

	if limiter.tr != mockTr {
		t.Error("RateLimiter transport not set correctly")
	}

	if limiter.limit == nil {
		t.Error("RateLimiter limit not initialized")
	}
}

func TestRateLimiterAllows(t *testing.T) {
	mockTr := &mockTransport{}
	// High rate limit to ensure requests pass through
	rl := NewRateLimiter(mockTr, 1000, 2000)

	req := httptest.NewRequest("GET", "http://example.com", nil)
	resp, err := rl.RoundTrip(req)

	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	if atomic.LoadInt32(&mockTr.callCount) != 1 {
		t.Errorf("Expected 1 call to underlying transport, got %d", mockTr.callCount)
	}
}

func TestRateLimiterBlocks(t *testing.T) {
	mockTr := &mockTransport{}
	// Very low rate limit
	rl := NewRateLimiter(mockTr, 1, 1)

	req := httptest.NewRequest("GET", "http://example.com", nil)

	// First request should pass
	resp1, err := rl.RoundTrip(req)
	if err != nil {
		t.Fatalf("First request returned error: %v", err)
	}
	if resp1.StatusCode != http.StatusOK {
		t.Errorf("First request: expected status %d, got %d", http.StatusOK, resp1.StatusCode)
	}

	// Immediately send more requests - should hit rate limit
	blocked := 0
	for i := 0; i < 10; i++ {
		resp, err := rl.RoundTrip(req)
		if err != nil {
			t.Fatalf("Request %d returned error: %v", i, err)
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			blocked++
		}
	}

	if blocked == 0 {
		t.Error("Expected some requests to be blocked, but none were")
	}
}

func TestRateLimiterBurst(t *testing.T) {
	mockTr := &mockTransport{}
	// Rate: 10/sec, Burst: 5
	rl := NewRateLimiter(mockTr, 10, 5)

	req := httptest.NewRequest("GET", "http://example.com", nil)

	// Should be able to send burst of 5 requests immediately
	successCount := 0
	for i := 0; i < 5; i++ {
		resp, err := rl.RoundTrip(req)
		if err != nil {
			t.Fatalf("Burst request %d returned error: %v", i, err)
		}
		if resp.StatusCode == http.StatusOK {
			successCount++
		}
	}

	if successCount < 5 {
		t.Errorf("Expected at least 5 successful burst requests, got %d", successCount)
	}

	// Next request should be rate limited
	resp, err := rl.RoundTrip(req)
	if err != nil {
		t.Fatalf("Post-burst request returned error: %v", err)
	}
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("Expected post-burst request to be rate limited, got status %d", resp.StatusCode)
	}
}

func TestRateLimiterConcurrent(t *testing.T) {
	mockTr := &mockTransport{}
	// Moderate rate limit
	rl := NewRateLimiter(mockTr, 50, 100)

	req := httptest.NewRequest("GET", "http://example.com", nil)

	var wg sync.WaitGroup
	successCount := int32(0)
	rateLimitedCount := int32(0)
	errorCount := int32(0)

	// Send 200 concurrent requests
	numRequests := 200
	wg.Add(numRequests)

	for i := 0; i < numRequests; i++ {
		go func() {
			defer wg.Done()
			resp, err := rl.RoundTrip(req)
			if err != nil {
				atomic.AddInt32(&errorCount, 1)
				return
			}
			if resp.StatusCode == http.StatusOK {
				atomic.AddInt32(&successCount, 1)
			} else if resp.StatusCode == http.StatusTooManyRequests {
				atomic.AddInt32(&rateLimitedCount, 1)
			}
		}()
	}

	wg.Wait()

	if errorCount > 0 {
		t.Errorf("Unexpected errors: %d", errorCount)
	}

	// Should have some successful and some rate-limited requests
	if successCount == 0 {
		t.Error("Expected some successful requests")
	}
	if rateLimitedCount == 0 {
		t.Error("Expected some rate-limited requests")
	}

	// Total should match
	total := successCount + rateLimitedCount + errorCount
	if total != int32(numRequests) {
		t.Errorf("Expected %d total responses, got %d", numRequests, total)
	}
}

func TestRateLimiterRecovery(t *testing.T) {
	mockTr := &mockTransport{}
	// 10 requests/sec, burst of 2
	rl := NewRateLimiter(mockTr, 10, 2)

	req := httptest.NewRequest("GET", "http://example.com", nil)

	// Exhaust burst
	for i := 0; i < 3; i++ {
		rl.RoundTrip(req)
	}

	// Should be rate limited now
	resp, _ := rl.RoundTrip(req)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Error("Expected rate limit after exhausting burst")
	}

	// Wait for rate limit to recover (100ms = 1 token for 10/sec rate)
	time.Sleep(150 * time.Millisecond)

	// Should be able to send request again
	resp, err := rl.RoundTrip(req)
	if err != nil {
		t.Fatalf("Request after recovery returned error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected successful request after recovery, got status %d", resp.StatusCode)
	}
}

func TestRateLimiterRespectsTooManyRequests(t *testing.T) {
	mockTr := &mockTransport{}
	rl := NewRateLimiter(mockTr, 1, 1)

	req := httptest.NewRequest("GET", "http://example.com", nil)

	// First request passes
	rl.RoundTrip(req)

	// Second request should be rate limited
	resp, err := rl.RoundTrip(req)
	if err != nil {
		t.Fatalf("Rate limited request returned error: %v", err)
	}

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("Expected status %d, got %d", http.StatusTooManyRequests, resp.StatusCode)
	}

	if resp.Request != req {
		t.Error("Response should include original request")
	}

	if resp.Body != http.NoBody {
		t.Error("Response should have NoBody")
	}
}

// Benchmark tests

func BenchmarkRateLimiter(b *testing.B) {
	b.ReportAllocs()
	mockTr := &mockTransport{}
	// High rate limit to minimize blocking in benchmark
	rl := NewRateLimiter(mockTr, 1000000, 1000000)

	req := httptest.NewRequest("GET", "http://example.com", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.RoundTrip(req)
	}
}

func BenchmarkRateLimiterParallel(b *testing.B) {
	b.ReportAllocs()
	mockTr := &mockTransport{}
	rl := NewRateLimiter(mockTr, 1000000, 1000000)

	req := httptest.NewRequest("GET", "http://example.com", nil)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rl.RoundTrip(req)
		}
	})
}

func BenchmarkRateLimiterWithBlocking(b *testing.B) {
	b.ReportAllocs()
	mockTr := &mockTransport{}
	// Lower rate to simulate realistic rate limiting
	rl := NewRateLimiter(mockTr, 100, 200)

	req := httptest.NewRequest("GET", "http://example.com", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.RoundTrip(req)
	}
}
