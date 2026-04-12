package transport

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRetryTransport_Success(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	transport := NewRetryTransport(http.DefaultTransport, 3)
	client := &http.Client{Transport: transport}

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)

	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Should only make one attempt for successful request
	if attempts != 1 {
		t.Errorf("expected 1 attempt, got %d", attempts)
	}
}

func TestRetryTransport_RetryOn503(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("Service Unavailable"))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}
	}))
	defer server.Close()

	transport := NewRetryTransport(http.DefaultTransport, 5)
	transport.InitialDelay = 10 * time.Millisecond // Speed up test
	client := &http.Client{Transport: transport}

	start := time.Now()
	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Should have retried twice before succeeding
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}

	// Should have some delay from retries
	if elapsed < 10*time.Millisecond {
		t.Errorf("expected some retry delay, got %v", elapsed)
	}
}

func TestRetryTransport_ExhaustRetries(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	transport := NewRetryTransport(http.DefaultTransport, 3)
	transport.InitialDelay = 10 * time.Millisecond
	client := &http.Client{Transport: transport}

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)

	if err != nil {
		t.Fatalf("request failed with error: %v", err)
	}
	defer resp.Body.Close()

	// Should still return response even after exhausting retries
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected status 502, got %d", resp.StatusCode)
	}

	// Should have made initial attempt + 3 retries = 4 total
	if attempts != 4 {
		t.Errorf("expected 4 attempts (1 initial + 3 retries), got %d", attempts)
	}
}

func TestRetryTransport_NoRetryOn200(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := NewRetryTransport(http.DefaultTransport, 3)
	client := &http.Client{Transport: transport}

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)

	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should only attempt once
	if attempts != 1 {
		t.Errorf("expected 1 attempt for successful request, got %d", attempts)
	}
}

func TestRetryTransport_NoRetryOn404(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	transport := NewRetryTransport(http.DefaultTransport, 3)
	client := &http.Client{Transport: transport}

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)

	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should only attempt once (404 is not retryable by default)
	if attempts != 1 {
		t.Errorf("expected 1 attempt for 404, got %d", attempts)
	}
}

func TestRetryTransport_CustomRetryFunc(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(http.StatusNotFound) // Normally not retryable
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	transport := NewRetryTransport(http.DefaultTransport, 3)
	transport.InitialDelay = 10 * time.Millisecond
	// Custom function that retries on 404
	transport.RetryableFunc = func(resp *http.Response, err error) bool {
		return err != nil || (resp != nil && resp.StatusCode == http.StatusNotFound)
	}

	client := &http.Client{Transport: transport}

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)

	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should have retried on 404 with custom function
	if attempts != 2 {
		t.Errorf("expected 2 attempts with custom retry function, got %d", attempts)
	}
}

func TestRetryTransport_ContextCancellation(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	transport := NewRetryTransport(http.DefaultTransport, 10)
	transport.InitialDelay = 100 * time.Millisecond
	client := &http.Client{Transport: transport}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
	_, err := client.Do(req)

	// Should fail with context error
	if err == nil {
		t.Fatal("expected context error, got nil")
	}

	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "context") {
		t.Errorf("expected context error, got: %v", err)
	}

	// Should have only made 1 attempt before context cancelled during backoff
	if attempts > 2 {
		t.Errorf("expected few attempts before cancellation, got %d", attempts)
	}
}

func TestRetryTransport_ExponentialBackoff(t *testing.T) {
	transport := NewRetryTransport(http.DefaultTransport, 5)
	transport.InitialDelay = 100 * time.Millisecond
	transport.BackoffMultiplier = 2.0
	transport.Jitter = 0 // Disable jitter for predictable testing

	// Test backoff calculation
	delays := []time.Duration{
		transport.calculateBackoff(0), // 100ms
		transport.calculateBackoff(1), // 200ms
		transport.calculateBackoff(2), // 400ms
		transport.calculateBackoff(3), // 800ms
	}

	expected := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		400 * time.Millisecond,
		800 * time.Millisecond,
	}

	for i, delay := range delays {
		if delay != expected[i] {
			t.Errorf("attempt %d: expected delay %v, got %v", i, expected[i], delay)
		}
	}
}

func TestRetryTransport_MaxDelay(t *testing.T) {
	transport := NewRetryTransport(http.DefaultTransport, 10)
	transport.InitialDelay = 100 * time.Millisecond
	transport.BackoffMultiplier = 2.0
	transport.MaxDelay = 500 * time.Millisecond
	transport.Jitter = 0

	// After several attempts, delay should cap at MaxDelay
	delay := transport.calculateBackoff(10) // Would be 102.4 seconds without cap

	if delay > transport.MaxDelay {
		t.Errorf("delay %v exceeds MaxDelay %v", delay, transport.MaxDelay)
	}

	// Should be capped at max delay
	if delay != transport.MaxDelay {
		t.Errorf("expected delay to be capped at %v, got %v", transport.MaxDelay, delay)
	}
}

func TestMakeRequestRetryable(t *testing.T) {
	body := "test request body"
	req, _ := http.NewRequest("POST", "http://example.com", strings.NewReader(body))

	err := MakeRequestRetryable(req)
	if err != nil {
		t.Fatalf("MakeRequestRetryable failed: %v", err)
	}

	// Verify GetBody is set
	if req.GetBody == nil {
		t.Fatal("GetBody should be set after MakeRequestRetryable")
	}

	// Verify body can be read multiple times
	body1, _ := io.ReadAll(req.Body)
	req.Body.Close()

	body2Reader, _ := req.GetBody()
	body2, _ := io.ReadAll(body2Reader)
	body2Reader.Close()

	if string(body1) != body || string(body2) != body {
		t.Errorf("body not retryable: got %q and %q, expected %q", body1, body2, body)
	}
}
