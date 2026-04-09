package transport

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestConnectionLimiter_BasicFunctionality(t *testing.T) {
	// Create a test server that takes some time to respond
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	// Create a base transport
	baseTransport := &http.Transport{}
	defer baseTransport.CloseIdleConnections()

	// Create connection limiter with limit of 2
	limiter := NewConnectionLimiter(baseTransport, 2)
	client := &http.Client{Transport: limiter}

	// Test that we can make requests up to the limit
	var wg sync.WaitGroup
	responses := make(chan *http.Response, 5)

	// Start 5 concurrent requests
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(server.URL)
			if err != nil {
				t.Errorf("Request failed: %v", err)
				return
			}
			responses <- resp
		}()
	}

	wg.Wait()
	close(responses)

	// Count responses by status code
	statusCounts := make(map[int]int)
	for resp := range responses {
		statusCounts[resp.StatusCode]++
		resp.Body.Close()
	}

	// Should have 2 successful requests (200) and 3 rejected requests (503)
	if statusCounts[200] != 2 {
		t.Errorf("Expected 2 successful requests, got %d", statusCounts[200])
	}
	if statusCounts[503] != 3 {
		t.Errorf("Expected 3 rejected requests, got %d", statusCounts[503])
	}
}

func TestConnectionLimiter_NoLimit(t *testing.T) {
	// Test that when maxConnections is 0, no limiting is applied
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	baseTransport := &http.Transport{}
	defer baseTransport.CloseIdleConnections()

	// Create limiter with 0 limit (should return original transport)
	limiter := NewConnectionLimiter(baseTransport, 0)

	// Should be the same as base transport
	if limiter != baseTransport {
		t.Error("Expected limiter to be the same as base transport when maxConnections is 0")
	}
}

func TestConnectionLimiter_NegativeLimit(t *testing.T) {
	// Test that when maxConnections is negative, no limiting is applied
	baseTransport := &http.Transport{}

	limiter := NewConnectionLimiter(baseTransport, -1)

	// Should be the same as base transport
	if limiter != baseTransport {
		t.Error("Expected limiter to be the same as base transport when maxConnections is negative")
	}
}

func TestConnectionLimiter_ActiveConnections(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	baseTransport := &http.Transport{}
	defer baseTransport.CloseIdleConnections()

	limiter := NewConnectionLimiter(baseTransport, 3)
	client := &http.Client{Transport: limiter}

	// Start 3 concurrent requests
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client.Get(server.URL)
		}()
	}

	// Wait a bit for requests to start
	time.Sleep(50 * time.Millisecond)

	// Check active connections
	cl := limiter.(*ConnectionLimiter)
	activeCount := cl.GetActiveConnections()
	if activeCount != 3 {
		t.Errorf("Expected 3 active connections, got %d", activeCount)
	}

	// Wait for all requests to complete
	wg.Wait()

	// Check that all connections are released
	activeCount = cl.GetActiveConnections()
	if activeCount != 0 {
		t.Errorf("Expected 0 active connections after completion, got %d", activeCount)
	}
}

func TestConnectionLimiter_WaitForAllConnections(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	baseTransport := &http.Transport{}
	defer baseTransport.CloseIdleConnections()

	limiter := NewConnectionLimiter(baseTransport, 2)
	client := &http.Client{Transport: limiter}

	// Start 2 concurrent requests
	var wg sync.WaitGroup
	started := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			started <- struct{}{}
			client.Get(server.URL)
		}()
	}

	// Ensure both requests have started
	<-started
	<-started

	// Wait for all connections to complete
	cl := limiter.(*ConnectionLimiter)
	cl.WaitForAllConnections()

	// Check that all connections are released
	activeCount := cl.GetActiveConnections()
	if activeCount != 0 {
		t.Errorf("Expected 0 active connections after WaitForAllConnections, got %d", activeCount)
	}
}

func TestConnectionLimiter_WaitForAllConnectionsWithTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	baseTransport := &http.Transport{}
	defer baseTransport.CloseIdleConnections()

	limiter := NewConnectionLimiter(baseTransport, 2)
	client := &http.Client{Transport: limiter}

	// Start 2 concurrent requests and ensure they are in-flight before waiting
	var wg sync.WaitGroup
	started := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			started <- struct{}{}
			client.Get(server.URL)
		}()
	}
	// Wait until both goroutines have signaled start
	<-started
	<-started

	// Wait with timeout that should succeed
	cl := limiter.(*ConnectionLimiter)
	success := cl.WaitForAllConnectionsWithTimeout(500 * time.Millisecond)
	if !success {
		t.Error("Expected WaitForAllConnectionsWithTimeout to succeed")
	}

	// Wait for all to complete
	wg.Wait()
}

func TestConnectionLimiter_GetMaxConnections(t *testing.T) {
	baseTransport := &http.Transport{}

	limiter := NewConnectionLimiter(baseTransport, 5)
	cl := limiter.(*ConnectionLimiter)

	maxConnections := cl.GetMaxConnections()
	if maxConnections != 5 {
		t.Errorf("Expected max connections to be 5, got %d", maxConnections)
	}
}

func TestConnectionLimiter_ConcurrentAccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	baseTransport := &http.Transport{}
	defer baseTransport.CloseIdleConnections()

	limiter := NewConnectionLimiter(baseTransport, 10)
	client := &http.Client{Transport: limiter}

	// Start many concurrent requests to test thread safety
	var wg sync.WaitGroup
	numRequests := 100

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client.Get(server.URL)
		}()
	}

	wg.Wait()

	// Check that all connections are released
	cl := limiter.(*ConnectionLimiter)
	activeCount := cl.GetActiveConnections()
	if activeCount != 0 {
		t.Errorf("Expected 0 active connections after completion, got %d", activeCount)
	}
}
