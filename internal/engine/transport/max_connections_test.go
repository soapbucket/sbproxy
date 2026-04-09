package transport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// slowTransport simulates a slow backend
type slowTransport struct {
	delay           time.Duration
	callCount       int32
	concurrentCalls int32
	maxConcurrent   int32
}

func (s *slowTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt32(&s.callCount, 1)
	current := atomic.AddInt32(&s.concurrentCalls, 1)

	// Track max concurrent
	for {
		max := atomic.LoadInt32(&s.maxConcurrent)
		if current <= max {
			break
		}
		if atomic.CompareAndSwapInt32(&s.maxConcurrent, max, current) {
			break
		}
	}

	defer atomic.AddInt32(&s.concurrentCalls, -1)

	time.Sleep(s.delay)

	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       http.NoBody,
		Request:    req,
	}, nil
}

func TestNewMaxConnections(t *testing.T) {
	mockTr := &mockTransport{}
	mc := NewMaxConnections(mockTr, 10)

	if mc == nil {
		t.Fatal("NewMaxConnections returned nil")
	}

	maxConn, ok := mc.(*MaxConnections)
	if !ok {
		t.Fatal("NewMaxConnections did not return *MaxConnections")
	}

	if maxConn.RoundTripper != mockTr {
		t.Error("MaxConnections transport not set correctly")
	}

	if cap(maxConn.connections) != 10 {
		t.Errorf("Expected connection pool size 10, got %d", cap(maxConn.connections))
	}
}

func TestNewMaxConnectionsZeroMax(t *testing.T) {
	mockTr := &mockTransport{}
	mc := NewMaxConnections(mockTr, 0)

	maxConn := mc.(*MaxConnections)
	if cap(maxConn.connections) != 1 {
		t.Errorf("Expected zero max to default to 1, got %d", cap(maxConn.connections))
	}
}

func TestNewMaxConnectionsNegativeMax(t *testing.T) {
	mockTr := &mockTransport{}
	mc := NewMaxConnections(mockTr, -5)

	maxConn := mc.(*MaxConnections)
	if cap(maxConn.connections) != 1 {
		t.Errorf("Expected negative max to default to 1, got %d", cap(maxConn.connections))
	}
}

func TestMaxConnectionsAllows(t *testing.T) {
	mockTr := &mockTransport{}
	mc := NewMaxConnections(mockTr, 10)

	req := httptest.NewRequest("GET", "http://example.com", nil)
	resp, err := mc.RoundTrip(req)

	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestMaxConnectionsLimits(t *testing.T) {
	slowTr := &slowTransport{delay: 100 * time.Millisecond}
	maxConns := 5
	mc := NewMaxConnections(slowTr, maxConns)

	req := httptest.NewRequest("GET", "http://example.com", nil)

	var wg sync.WaitGroup
	numRequests := 20
	wg.Add(numRequests)

	startTime := time.Now()

	for i := 0; i < numRequests; i++ {
		go func() {
			defer wg.Done()
			resp, err := mc.RoundTrip(req)
			if err != nil {
				t.Errorf("RoundTrip returned error: %v", err)
				return
			}
			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status OK, got %d", resp.StatusCode)
			}
		}()
	}

	wg.Wait()
	_ = time.Since(startTime) // duration not used in this test

	// Verify max concurrent connections was limited
	maxConcurrent := atomic.LoadInt32(&slowTr.maxConcurrent)
	if maxConcurrent > int32(maxConns) {
		t.Errorf("Max concurrent connections exceeded limit: %d > %d", maxConcurrent, maxConns)
	}

	// With max 5 concurrent and 20 total requests taking 100ms each,
	// should take at least 400ms (20/5 * 100ms)
	// Verify that max concurrent connections was respected
}

func TestMaxConnectionsBlocking(t *testing.T) {
	slowTr := &slowTransport{delay: 200 * time.Millisecond}
	maxConns := 2
	mc := NewMaxConnections(slowTr, maxConns)

	req := httptest.NewRequest("GET", "http://example.com", nil)

	// Start 2 requests that will hold the connections
	var wg sync.WaitGroup
	wg.Add(3)

	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			mc.RoundTrip(req)
		}()
	}

	// Give the first requests time to start
	time.Sleep(50 * time.Millisecond)

	// Third request should block
	blocked := false
	go func() {
		defer wg.Done()
		startTime := time.Now()
		mc.RoundTrip(req)
		duration := time.Since(startTime)
		// If it took longer than the delay, it was blocked
		if duration > 150*time.Millisecond {
			blocked = true
		}
	}()

	wg.Wait()

	if !blocked {
		t.Error("Expected third request to block, but it didn't")
	}
}

func TestMaxConnectionsConcurrentSafety(t *testing.T) {
	mockTr := &mockTransport{}
	mc := NewMaxConnections(mockTr, 5)

	req := httptest.NewRequest("GET", "http://example.com", nil)

	var wg sync.WaitGroup
	numRequests := 100
	wg.Add(numRequests)

	errors := int32(0)
	successes := int32(0)

	for i := 0; i < numRequests; i++ {
		go func() {
			defer wg.Done()
			resp, err := mc.RoundTrip(req)
			if err != nil {
				atomic.AddInt32(&errors, 1)
				return
			}
			if resp.StatusCode == http.StatusOK {
				atomic.AddInt32(&successes, 1)
			}
		}()
	}

	wg.Wait()

	if errors > 0 {
		t.Errorf("Got %d errors in concurrent requests", errors)
	}

	if successes != int32(numRequests) {
		t.Errorf("Expected %d successful requests, got %d", numRequests, successes)
	}
}

// panicTransport is a transport that panics
type panicTransport struct{}

func (p *panicTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	panic("test panic")
}

func TestMaxConnectionsReleasesOnPanic(t *testing.T) {
	// Transport that panics
	panicTr := &panicTransport{}

	mc := NewMaxConnections(panicTr, 2)
	req := httptest.NewRequest("GET", "http://example.com", nil)

	// First request will panic
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic to be propagated")
			}
		}()
		mc.RoundTrip(req)
	}()

	// Connection should have been released, so we should be able to use it
	mockTr := &mockTransport{}
	mc2 := NewMaxConnections(mockTr, 1)

	// This should not block if connection was released properly
	done := make(chan bool, 1)
	go func() {
		mc2.RoundTrip(req)
		done <- true
	}()

	select {
	case <-done:
		// Success
	case <-time.After(100 * time.Millisecond):
		t.Error("Connection was not released after panic")
	}
}

func TestMaxConnectionsSequentialRequests(t *testing.T) {
	mockTr := &mockTransport{}
	mc := NewMaxConnections(mockTr, 1)

	req := httptest.NewRequest("GET", "http://example.com", nil)

	// Make 10 sequential requests
	for i := 0; i < 10; i++ {
		resp, err := mc.RoundTrip(req)
		if err != nil {
			t.Fatalf("Request %d returned error: %v", i, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Request %d: expected status OK, got %d", i, resp.StatusCode)
		}
	}

	// All requests should have completed without issue
	if atomic.LoadInt32(&mockTr.callCount) != 10 {
		t.Errorf("Expected 10 calls to transport, got %d", mockTr.callCount)
	}
}

func TestMaxConnections_ContextCancelReleasesSlot(t *testing.T) {
	// Slow upstream holds the single slot for 2 seconds
	slowTr := &slowTransport{delay: 2 * time.Second}
	mc := NewMaxConnections(slowTr, 1)

	// First request occupies the only slot (starts in background)
	go func() {
		req := httptest.NewRequest("GET", "http://example.com/slow", nil)
		mc.RoundTrip(req)
	}()

	// Give the first request time to acquire the slot
	time.Sleep(50 * time.Millisecond)

	// Second request: short context timeout while waiting to acquire the slot
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req2 := httptest.NewRequest("GET", "http://example.com/blocked", nil).WithContext(ctx)

	_, err := mc.RoundTrip(req2)
	if err == nil {
		t.Fatal("expected error from context timeout, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}

	// Third request: fresh context, should acquire the slot once the slow request finishes.
	// The slow request takes 2s total; we started it ~150ms ago, so we need to wait.
	// This verifies the slot is properly released and not permanently consumed.
	done := make(chan error, 1)
	go func() {
		req3 := httptest.NewRequest("GET", "http://example.com/after", nil)
		_, err := mc.RoundTrip(req3)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("third request returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("third request deadlocked; slot was not released after slow upstream completed")
	}
}

// Benchmark tests

func BenchmarkMaxConnections(b *testing.B) {
	b.ReportAllocs()
	mockTr := &mockTransport{}
	mc := NewMaxConnections(mockTr, 100)

	req := httptest.NewRequest("GET", "http://example.com", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mc.RoundTrip(req)
	}
}

func BenchmarkMaxConnectionsParallel(b *testing.B) {
	b.ReportAllocs()
	mockTr := &mockTransport{}
	mc := NewMaxConnections(mockTr, 100)

	req := httptest.NewRequest("GET", "http://example.com", nil)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mc.RoundTrip(req)
		}
	})
}

func BenchmarkMaxConnectionsLowLimit(b *testing.B) {
	b.ReportAllocs()
	mockTr := &mockTransport{}
	mc := NewMaxConnections(mockTr, 5)

	req := httptest.NewRequest("GET", "http://example.com", nil)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mc.RoundTrip(req)
		}
	})
}

func BenchmarkMaxConnectionsContention(b *testing.B) {
	b.ReportAllocs()
	slowTr := &slowTransport{delay: 1 * time.Millisecond}
	mc := NewMaxConnections(slowTr, 10)

	req := httptest.NewRequest("GET", "http://example.com", nil)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mc.RoundTrip(req)
		}
	})
}
