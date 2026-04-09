package config

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestExecuteHTTPCallout_Success(t *testing.T) {
	calloutServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Enriched", "user-123")
		w.Header().Set("X-Score", "42")
		w.Header().Set("Content-Type", "text/plain") // Non X- header, should not be injected
		w.WriteHeader(http.StatusOK)
	}))
	defer calloutServer.Close()

	cfg := &HTTPCalloutConfig{
		URL:     calloutServer.URL,
		Timeout: reqctx.Duration{Duration: 5 * time.Second},
	}

	req := httptest.NewRequest("GET", "http://example.com/api", nil)

	err := ExecuteHTTPCallout(cfg, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// X-Enriched should be injected
	if req.Header.Get("X-Enriched") != "user-123" {
		t.Errorf("expected X-Enriched=user-123, got %q", req.Header.Get("X-Enriched"))
	}

	// X-Score should be injected
	if req.Header.Get("X-Score") != "42" {
		t.Errorf("expected X-Score=42, got %q", req.Header.Get("X-Score"))
	}

	// Content-Type (non X- header) should NOT be injected
	if req.Header.Get("Content-Type") != "" {
		t.Errorf("expected Content-Type to not be injected, got %q", req.Header.Get("Content-Type"))
	}
}

func TestExecuteHTTPCallout_FailOpen(t *testing.T) {
	// Server that returns 500
	calloutServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer calloutServer.Close()

	cfg := &HTTPCalloutConfig{
		URL:      calloutServer.URL,
		FailMode: "open",
		Timeout:  reqctx.Duration{Duration: 5 * time.Second},
	}

	req := httptest.NewRequest("GET", "http://example.com/api", nil)

	err := ExecuteHTTPCallout(cfg, req)
	if err != nil {
		t.Fatalf("fail_open should not return error, got: %v", err)
	}
}

func TestExecuteHTTPCallout_FailClosed(t *testing.T) {
	// Server that returns 500
	calloutServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer calloutServer.Close()

	cfg := &HTTPCalloutConfig{
		URL:      calloutServer.URL,
		FailMode: "closed",
		Timeout:  reqctx.Duration{Duration: 5 * time.Second},
	}

	req := httptest.NewRequest("GET", "http://example.com/api", nil)

	err := ExecuteHTTPCallout(cfg, req)
	if err == nil {
		t.Fatal("fail_closed should return error on upstream failure")
	}
}

func TestExecuteHTTPCallout_ConnectionError_FailOpen(t *testing.T) {
	cfg := &HTTPCalloutConfig{
		URL:      "http://127.0.0.1:1", // Nothing listening
		FailMode: "open",
		Timeout:  reqctx.Duration{Duration: 1 * time.Second},
	}

	req := httptest.NewRequest("GET", "http://example.com/api", nil)

	err := ExecuteHTTPCallout(cfg, req)
	if err != nil {
		t.Fatalf("fail_open should not return error on connection failure, got: %v", err)
	}
}

func TestExecuteHTTPCallout_ConnectionError_FailClosed(t *testing.T) {
	cfg := &HTTPCalloutConfig{
		URL:      "http://127.0.0.1:1", // Nothing listening
		FailMode: "closed",
		Timeout:  reqctx.Duration{Duration: 1 * time.Second},
	}

	req := httptest.NewRequest("GET", "http://example.com/api", nil)

	err := ExecuteHTTPCallout(cfg, req)
	if err == nil {
		t.Fatal("fail_closed should return error on connection failure")
	}
}

func TestExecuteHTTPCallout_NilConfig(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/api", nil)

	err := ExecuteHTTPCallout(nil, req)
	if err != nil {
		t.Fatalf("nil config should not return error, got: %v", err)
	}
}

func TestExecuteHTTPCallout_EmptyURL(t *testing.T) {
	cfg := &HTTPCalloutConfig{
		URL: "",
	}

	req := httptest.NewRequest("GET", "http://example.com/api", nil)

	err := ExecuteHTTPCallout(cfg, req)
	if err != nil {
		t.Fatalf("empty URL should not return error, got: %v", err)
	}
}

func TestExecuteHTTPCallout_ForwardsHeaders(t *testing.T) {
	var receivedHeaders http.Header

	calloutServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.Header().Set("X-Result", "ok")
		w.WriteHeader(http.StatusOK)
	}))
	defer calloutServer.Close()

	cfg := &HTTPCalloutConfig{
		URL:    calloutServer.URL,
		Method: "POST",
		Headers: map[string]string{
			"Authorization": "Bearer test-token",
			"X-Request-ID":  "req-123",
		},
		Timeout: reqctx.Duration{Duration: 5 * time.Second},
	}

	req := httptest.NewRequest("GET", "http://example.com/api", nil)

	err := ExecuteHTTPCallout(cfg, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedHeaders.Get("Authorization") != "Bearer test-token" {
		t.Errorf("expected Authorization header forwarded, got %q", receivedHeaders.Get("Authorization"))
	}
	if receivedHeaders.Get("X-Request-ID") != "req-123" {
		t.Errorf("expected X-Request-ID header forwarded, got %q", receivedHeaders.Get("X-Request-ID"))
	}
}

func TestExecuteHTTPCallout_DefaultMethod(t *testing.T) {
	var receivedMethod string

	calloutServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer calloutServer.Close()

	cfg := &HTTPCalloutConfig{
		URL:     calloutServer.URL,
		Timeout: reqctx.Duration{Duration: 5 * time.Second},
	}

	req := httptest.NewRequest("GET", "http://example.com/api", nil)

	err := ExecuteHTTPCallout(cfg, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedMethod != "GET" {
		t.Errorf("expected default method GET, got %q", receivedMethod)
	}
}
