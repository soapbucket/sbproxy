package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewProxy(t *testing.T) {
	flushInterval := 100 * time.Millisecond
	retryDelay := 1 * time.Second
	maxRetryCount := 3
	debug := true

	proxy := NewProxy(flushInterval, retryDelay, maxRetryCount, nil, nil, nil, debug)

	if proxy == nil {
		t.Error("Expected proxy to be non-nil")
	}

	// Test that it implements http.Handler
	var _ http.Handler = proxy
}

func TestProxy_ServeHTTP(t *testing.T) {
	// Create a test server that will be proxied to
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, World!"))
	}))
	defer backend.Close()

	// Create proxy with custom transport
	transport := &http.Transport{}
	proxy := NewProxy(100*time.Millisecond, 1*time.Second, 3, nil, nil, transport, false)

	// Create test request
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	w := httptest.NewRecorder()

	// Test that proxy can be called without panicking
	// Note: This will fail because we don't have a real backend, but it tests the structure
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Proxy panicked: %v", r)
		}
	}()

	proxy.ServeHTTP(w, req)
}

func TestProxy_DefaultValues(t *testing.T) {
	proxy := &Proxy{}

	// Test default values
	if proxy.maxRetryCount != 0 {
		t.Errorf("Expected maxRetryCount to be 0, got %d", proxy.maxRetryCount)
	}

	if proxy.retryDelay != 0 {
		t.Errorf("Expected retryDelay to be 0, got %v", proxy.retryDelay)
	}

	if proxy.flushInterval != 0 {
		t.Errorf("Expected flushInterval to be 0, got %v", proxy.flushInterval)
	}

	if proxy.maxRequestTime != 0 {
		t.Errorf("Expected maxRequestTime to be 0, got %v", proxy.maxRequestTime)
	}
}

func TestMakeProxyRequest(t *testing.T) {
	// Create a test server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	}))
	defer backend.Close()

	// Create test request
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	w := httptest.NewRecorder()

	// Test proxy handler
	transport := &http.Transport{}
	flushInterval := 100 * time.Millisecond
	retryDelay := 1 * time.Second
	maxRetryCount := 3

	// This should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("makeProxyRequest panicked: %v", r)
		}
	}()

	// Test the proxy handler
	proxy := NewProxy(flushInterval, retryDelay, maxRetryCount, nil, nil, transport, false)
	proxy.ServeHTTP(w, req)
}
