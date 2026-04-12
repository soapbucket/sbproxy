package transport

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestCoalescingTransport_BasicCoalescing(t *testing.T) {
	// Create a test server that counts requests
	requestCount := 0
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()
		time.Sleep(50 * time.Millisecond) // Simulate slow origin
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	// Create coalescing transport
	baseTransport := http.DefaultTransport
	config := CoalescingConfig{
		Enabled:        true,
		MaxInflight:    1000,
		CoalesceWindow: 100 * time.Millisecond,
		MaxWaiters:     100,
		KeyFunc:        DefaultCoalesceKey,
	}
	transport := NewCoalescingTransport(baseTransport, config)
	defer transport.Close()

	// Create multiple identical requests
	numRequests := 10
	var wg sync.WaitGroup
	results := make([]*http.Response, numRequests)
	errors := make([]error, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req, _ := http.NewRequest("GET", server.URL+"/test", nil)
			results[idx], errors[idx] = transport.RoundTrip(req)
		}(i)
	}

	wg.Wait()

	// Verify all requests succeeded
	for i, err := range errors {
		if err != nil {
			t.Errorf("Request %d failed: %v", i, err)
		}
		if results[i] == nil {
			t.Errorf("Request %d returned nil response", i)
		} else if results[i].StatusCode != http.StatusOK {
			t.Errorf("Request %d returned status %d, expected 200", i, results[i].StatusCode)
		}
	}

	// Verify only one request hit the origin
	mu.Lock()
	count := requestCount
	mu.Unlock()
	if count != 1 {
		t.Errorf("Expected 1 origin request, got %d", count)
	}
}

func TestCoalescingTransport_DifferentRequests(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(r.URL.Path))
	}))
	defer server.Close()

	// Create coalescing transport
	baseTransport := http.DefaultTransport
	config := CoalescingConfig{
		Enabled:        true,
		MaxInflight:    1000,
		CoalesceWindow: 100 * time.Millisecond,
		MaxWaiters:     100,
		KeyFunc:        DefaultCoalesceKey,
	}
	transport := NewCoalescingTransport(baseTransport, config)
	defer transport.Close()

	// Create different requests (different paths)
	req1, _ := http.NewRequest("GET", server.URL+"/path1", nil)
	req2, _ := http.NewRequest("GET", server.URL+"/path2", nil)

	resp1, err1 := transport.RoundTrip(req1)
	resp2, err2 := transport.RoundTrip(req2)

	if err1 != nil {
		t.Errorf("Request 1 failed: %v", err1)
	}
	if err2 != nil {
		t.Errorf("Request 2 failed: %v", err2)
	}

	// Both should succeed (not coalesced because different keys)
	if resp1.StatusCode != http.StatusOK || resp2.StatusCode != http.StatusOK {
		t.Errorf("Expected both requests to succeed")
	}
}

func TestCoalescingTransport_Disabled(t *testing.T) {
	// Create a test server that counts requests
	requestCount := 0
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create coalescing transport with coalescing disabled
	baseTransport := http.DefaultTransport
	config := CoalescingConfig{
		Enabled: false, // Disabled
	}
	transport := NewCoalescingTransport(baseTransport, config)
	defer transport.Close()

	// Create multiple identical requests
	numRequests := 5
	var wg sync.WaitGroup
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", server.URL+"/test", nil)
			transport.RoundTrip(req)
		}()
	}

	wg.Wait()

	// Verify all requests hit the origin (no coalescing)
	mu.Lock()
	count := requestCount
	mu.Unlock()
	if count != numRequests {
		t.Errorf("Expected %d origin requests (no coalescing), got %d", numRequests, count)
	}
}

func TestCoalescingTransport_ContextCancellation(t *testing.T) {
	// Create a slow test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create coalescing transport
	baseTransport := http.DefaultTransport
	config := CoalescingConfig{
		Enabled:        true,
		CoalesceWindow: 100 * time.Millisecond,
		MaxWaiters:     100,
		KeyFunc:        DefaultCoalesceKey,
	}
	transport := NewCoalescingTransport(baseTransport, config)
	defer transport.Close()

	// Create first request (will execute)
	req1, _ := http.NewRequest("GET", server.URL+"/test", nil)
	go transport.RoundTrip(req1)

	// Wait a bit for first request to start
	time.Sleep(10 * time.Millisecond)

	// Create second request with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately
	req2, _ := http.NewRequestWithContext(ctx, "GET", server.URL+"/test", nil)

	// This should return context error, not wait
	_, err := transport.RoundTrip(req2)
	if err == nil {
		t.Error("Expected context cancellation error")
	}
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled, got %v", err)
	}
}

func TestCoalescingTransport_MaxWaiters(t *testing.T) {
	// Create a slow test server that counts requests
	requestCount := 0
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create coalescing transport with low max waiters
	baseTransport := http.DefaultTransport
	config := CoalescingConfig{
		Enabled:        true,
		CoalesceWindow: 100 * time.Millisecond,
		MaxWaiters:     2, // Very low limit
		KeyFunc:        DefaultCoalesceKey,
	}
	transport := NewCoalescingTransport(baseTransport, config)
	defer transport.Close()

	// Create first request (will execute)
	req1, _ := http.NewRequest("GET", server.URL+"/test", nil)
	go transport.RoundTrip(req1)

	// Wait a bit for first request to start
	time.Sleep(20 * time.Millisecond)

	// Create multiple waiters (more than max)
	numWaiters := 5
	var wg sync.WaitGroup

	for i := 0; i < numWaiters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", server.URL+"/test", nil)
			transport.RoundTrip(req)
		}()
	}

	wg.Wait()

	// Some requests should have executed directly due to max waiters
	// We expect more than 1 request (the coalesced one) but less than all 6
	mu.Lock()
	count := requestCount
	mu.Unlock()
	if count <= 1 {
		t.Errorf("Expected more than 1 request (some should execute directly), got %d", count)
	}
	if count >= numWaiters+1 {
		t.Errorf("Expected some coalescing (less than %d requests), got %d", numWaiters+1, count)
	}
}

func TestCoalescingTransport_MaxInflight(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create coalescing transport with very low max inflight
	baseTransport := http.DefaultTransport
	config := CoalescingConfig{
		Enabled:        true,
		MaxInflight:    2, // Very low limit
		CoalesceWindow: 100 * time.Millisecond,
		MaxWaiters:     100,
		KeyFunc:        DefaultCoalesceKey,
	}
	transport := NewCoalescingTransport(baseTransport, config)
	defer transport.Close()

	// Create requests with different keys (so they don't coalesce)
	// This will test max inflight limit
	req1, _ := http.NewRequest("GET", server.URL+"/path1", nil)
	req2, _ := http.NewRequest("GET", server.URL+"/path2", nil)
	req3, _ := http.NewRequest("GET", server.URL+"/path3", nil)

	// Execute first two (should work)
	go transport.RoundTrip(req1)
	go transport.RoundTrip(req2)

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	// Third request should execute directly (max inflight exceeded)
	resp3, err3 := transport.RoundTrip(req3)
	if err3 != nil {
		t.Errorf("Request 3 should execute directly, got error: %v", err3)
	}
	if resp3 == nil || resp3.StatusCode != http.StatusOK {
		t.Errorf("Request 3 should succeed when executing directly")
	}
}

func TestDefaultCoalesceKey(t *testing.T) {
	req1, _ := http.NewRequest("GET", "https://example.com/test", nil)
	req2, _ := http.NewRequest("GET", "https://example.com/test", nil)
	req3, _ := http.NewRequest("GET", "https://example.com/other", nil)

	key1 := DefaultCoalesceKey(req1)
	key2 := DefaultCoalesceKey(req2)
	key3 := DefaultCoalesceKey(req3)

	// Same requests should have same key
	if key1 != key2 {
		t.Errorf("Expected same key for identical requests, got %s and %s", key1, key2)
	}

	// Different requests should have different keys
	if key1 == key3 {
		t.Errorf("Expected different keys for different requests")
	}
}

func TestMethodURLKey(t *testing.T) {
	req1, _ := http.NewRequest("GET", "https://example.com/test", nil)
	req2, _ := http.NewRequest("GET", "https://example.com/test", nil)
	req3, _ := http.NewRequest("POST", "https://example.com/test", nil)

	key1 := MethodURLKey(req1)
	key2 := MethodURLKey(req2)
	key3 := MethodURLKey(req3)

	// Same method + URL should have same key
	if key1 != key2 {
		t.Errorf("Expected same key for identical requests, got %s and %s", key1, key2)
	}

	// Different methods should have different keys
	if key1 == key3 {
		t.Errorf("Expected different keys for different methods")
	}
}

func TestDefaultCoalesceKey_DoesNotConsumeBodyWithoutGetBody(t *testing.T) {
	payload := "hello-body"
	req, _ := http.NewRequest("POST", "https://example.com/test", io.NopCloser(bytes.NewBufferString(payload)))
	req.GetBody = nil

	_ = DefaultCoalesceKey(req)

	remaining, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("failed reading request body after key generation: %v", err)
	}
	if string(remaining) != payload {
		t.Fatalf("expected body to remain intact, got %q", string(remaining))
	}
}

func TestCoalescingTransport_ResponseCloning(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test body"))
	}))
	defer server.Close()

	// Create coalescing transport
	baseTransport := http.DefaultTransport
	config := CoalescingConfig{
		Enabled:        true,
		CoalesceWindow: 100 * time.Millisecond,
		MaxWaiters:     100,
		KeyFunc:        DefaultCoalesceKey,
	}
	transport := NewCoalescingTransport(baseTransport, config)
	defer transport.Close()

	// Create multiple identical requests
	numRequests := 3
	var wg sync.WaitGroup
	bodies := make([][]byte, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req, _ := http.NewRequest("GET", server.URL+"/test", nil)
			resp, err := transport.RoundTrip(req)
			if err == nil && resp != nil && resp.Body != nil {
				bodies[idx], _ = io.ReadAll(resp.Body)
				resp.Body.Close()
			}
		}(i)
	}

	wg.Wait()

	// Verify all responses have the same body
	expectedBody := []byte("test body")
	for i, body := range bodies {
		if len(body) == 0 {
			t.Errorf("Request %d got empty body", i)
		} else if string(body) != string(expectedBody) {
			t.Errorf("Request %d got body %q, expected %q", i, string(body), string(expectedBody))
		}
	}
}
