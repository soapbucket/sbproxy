package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDelayTransport_Basic(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	// Create delay transport with 100ms delay
	transport := NewDelayTransport(http.DefaultTransport, 100*time.Millisecond)

	// Measure request time
	start := time.Now()

	req, _ := http.NewRequest("GET", server.URL, nil)
	client := &http.Client{Transport: transport}
	resp, err := client.Do(req)

	elapsed := time.Since(start)

	// Verify
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Should have delayed at least 100ms
	if elapsed < 100*time.Millisecond {
		t.Errorf("expected delay of at least 100ms, got %v", elapsed)
	}
}

func TestDelayTransport_WithFunc(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create delay function that delays POST requests more
	delayFunc := func(req *http.Request) time.Duration {
		if req.Method == "POST" {
			return 100 * time.Millisecond
		}
		return 0
	}

	transport := NewDelayTransportWithFunc(http.DefaultTransport, delayFunc)
	client := &http.Client{Transport: transport}

	// Test GET (no delay)
	start := time.Now()
	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	resp.Body.Close()
	getElapsed := time.Since(start)

	// Test POST (with delay)
	start = time.Now()
	req, _ = http.NewRequest("POST", server.URL, nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	resp.Body.Close()
	postElapsed := time.Since(start)

	// Verify POST took longer than GET
	if postElapsed < 100*time.Millisecond {
		t.Errorf("expected POST delay of at least 100ms, got %v", postElapsed)
	}

	if getElapsed > 50*time.Millisecond {
		t.Errorf("expected GET to have no significant delay, got %v", getElapsed)
	}
}

func TestDelayTransport_ContextCancellation(t *testing.T) {
	// Create test server that never responds
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create delay transport with long delay
	transport := NewDelayTransport(http.DefaultTransport, 500*time.Millisecond)

	// Create request with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
	client := &http.Client{Transport: transport}

	start := time.Now()
	_, err := client.Do(req)
	elapsed := time.Since(start)

	// Should fail with context error
	if err == nil {
		t.Fatal("expected context error, got nil")
	}

	// Should not wait the full delay (500ms) - should cancel around 100ms
	if elapsed > 200*time.Millisecond {
		t.Errorf("expected quick cancellation, took %v", elapsed)
	}
}

func TestDelayTransport_NoDelay(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create delay transport with 0 delay
	transport := NewDelayTransport(http.DefaultTransport, 0)

	start := time.Now()
	req, _ := http.NewRequest("GET", server.URL, nil)
	client := &http.Client{Transport: transport}
	resp, err := client.Do(req)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should be very fast (no artificial delay)
	if elapsed > 100*time.Millisecond {
		t.Errorf("expected fast request with no delay, took %v", elapsed)
	}
}
