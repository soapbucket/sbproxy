package rag

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	json "github.com/goccy/go-json"
)

func TestHTTPClient_Do_Success(t *testing.T) {
	t.Parallel()

	type reqPayload struct {
		Name string `json:"name"`
	}
	type respPayload struct {
		Message string `json:"message"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/test" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("missing Content-Type header")
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("missing Accept header")
		}

		var req reqPayload
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if req.Name != "test" {
			t.Errorf("unexpected name: %q", req.Name)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(respPayload{Message: "ok"})
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL)
	var result respPayload
	err := client.Do(context.Background(), "POST", "/api/test", reqPayload{Name: "test"}, &result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Message != "ok" {
		t.Errorf("expected message %q, got %q", "ok", result.Message)
	}
}

func TestHTTPClient_Do_AuthHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		opts       []HTTPClientOption
		wantHeader string
		wantValue  string
	}{
		{
			name:       "bearer auth",
			opts:       []HTTPClientOption{WithBearerAuth("my-token")},
			wantHeader: "Authorization",
			wantValue:  "Bearer my-token",
		},
		{
			name:       "api key auth",
			opts:       []HTTPClientOption{WithAPIKeyAuth("x-api-key", "secret-key")},
			wantHeader: "x-api-key",
			wantValue:  "secret-key",
		},
		{
			name:       "custom auth",
			opts:       []HTTPClientOption{WithAuth("X-Custom-Auth", "custom-value")},
			wantHeader: "X-Custom-Auth",
			wantValue:  "custom-value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got := r.Header.Get(tt.wantHeader)
				if got != tt.wantValue {
					t.Errorf("header %q: got %q, want %q", tt.wantHeader, got, tt.wantValue)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			client := NewHTTPClient(srv.URL, tt.opts...)
			err := client.Do(context.Background(), "GET", "/check", nil, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestHTTPClient_Do_CustomHeaders(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Workspace-ID") != "ws-123" {
			t.Errorf("missing custom header X-Workspace-ID")
		}
		if r.Header.Get("X-Request-Source") != "proxy" {
			t.Errorf("missing custom header X-Request-Source")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL,
		WithHeader("X-Workspace-ID", "ws-123"),
		WithHeader("X-Request-Source", "proxy"),
	)
	err := client.Do(context.Background(), "GET", "/test", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHTTPClient_Do_RetryOn429(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate limited"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL, WithRetries(3), WithBackoff(1*time.Millisecond))

	type resp struct {
		Status string `json:"status"`
	}
	var result resp
	err := client.Do(context.Background(), "GET", "/retry", nil, &result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", result.Status)
	}
	if got := attempts.Load(); got != 3 {
		t.Errorf("expected 3 attempts, got %d", got)
	}
}

func TestHTTPClient_Do_RetryOn5xx(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"server error"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL, WithRetries(2), WithBackoff(1*time.Millisecond))

	err := client.Do(context.Background(), "GET", "/retry5xx", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := attempts.Load(); got != 2 {
		t.Errorf("expected 2 attempts, got %d", got)
	}
}

func TestHTTPClient_Do_NoRetryOn4xx(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"bad request"}`))
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL, WithRetries(3), WithBackoff(1*time.Millisecond))

	err := client.Do(context.Background(), "GET", "/no-retry", nil, nil)
	if err == nil {
		t.Fatal("expected error for 400 response")
	}

	httpErr, ok := err.(*HTTPError)
	if !ok {
		t.Fatalf("expected *HTTPError, got %T", err)
	}
	if httpErr.StatusCode != 400 {
		t.Errorf("expected status 400, got %d", httpErr.StatusCode)
	}

	if got := attempts.Load(); got != 1 {
		t.Errorf("expected 1 attempt (no retry on 4xx), got %d", got)
	}
}

func TestHTTPClient_Do_AllRetriesFail(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"unavailable"}`))
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL, WithRetries(2), WithBackoff(1*time.Millisecond))

	err := client.Do(context.Background(), "GET", "/fail", nil, nil)
	if err == nil {
		t.Fatal("expected error after all retries exhausted")
	}
	if !strings.Contains(err.Error(), "all 3 attempts failed") {
		t.Errorf("unexpected error message: %q", err.Error())
	}
	// retries=2 means attempts = 1 (initial) + 2 (retries) = 3.
	if got := attempts.Load(); got != 3 {
		t.Errorf("expected 3 attempts, got %d", got)
	}
}

func TestHTTPClient_Do_ContextCancellation(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL, WithTimeout(10*time.Second))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := client.Do(ctx, "GET", "/slow", nil, nil)
	if err == nil {
		t.Fatal("expected error from context cancellation")
	}
}

func TestHTTPClient_Do_NilBody(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// When body is nil, Content-Type should not be set.
		if ct := r.Header.Get("Content-Type"); ct != "" {
			t.Errorf("expected no Content-Type for nil body, got %q", ct)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL)
	err := client.Do(context.Background(), "GET", "/no-body", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHTTPClient_DoRaw(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "text/plain" {
			t.Errorf("expected text/plain Content-Type, got %q", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("Authorization") != "Bearer raw-token" {
			t.Errorf("missing auth header")
		}
		if r.Header.Get("X-Custom") != "value" {
			t.Errorf("missing custom header")
		}

		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		w.Write(body) // Echo back.
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL,
		WithBearerAuth("raw-token"),
		WithHeader("X-Custom", "value"),
	)

	body := strings.NewReader("raw file content")
	respBody, status, err := client.DoRaw(context.Background(), "PUT", "/upload", body, "text/plain")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != 201 {
		t.Errorf("expected status 201, got %d", status)
	}
	if string(respBody) != "raw file content" {
		t.Errorf("unexpected response body: %q", string(respBody))
	}
}

func TestHTTPClient_DoRaw_NoContentType(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "" {
			t.Errorf("expected no Content-Type, got %q", ct)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL)
	_, status, err := client.DoRaw(context.Background(), "GET", "/test", nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != 200 {
		t.Errorf("expected status 200, got %d", status)
	}
}

func TestHTTPError_Error(t *testing.T) {
	t.Parallel()

	err := &HTTPError{StatusCode: 404, Body: "not found"}
	if got := err.Error(); got != "http 404: not found" {
		t.Errorf("unexpected error string: %q", got)
	}
}

func TestHTTPClient_WithTimeout(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL, WithTimeout(50*time.Millisecond))
	err := client.Do(context.Background(), "GET", "/timeout", nil, nil)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestHTTPClient_WithHTTPClient(t *testing.T) {
	t.Parallel()

	custom := &http.Client{Timeout: 1 * time.Second}
	client := NewHTTPClient("http://example.com", WithHTTPClient(custom))
	if client.base != custom {
		t.Error("expected custom HTTP client to be set")
	}
}

func TestHTTPClient_Do_UnmarshalError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`this is not valid json`))
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL)
	type result struct {
		Value string `json:"value"`
	}
	var r result
	err := client.Do(context.Background(), "GET", "/bad-json", nil, &r)
	if err == nil {
		t.Fatal("expected unmarshal error")
	}
	if !strings.Contains(err.Error(), "unmarshal response") {
		t.Errorf("unexpected error: %q", err.Error())
	}
}

func TestNewHTTPClient_Defaults(t *testing.T) {
	t.Parallel()

	client := NewHTTPClient("http://example.com")
	if client.baseURL != "http://example.com" {
		t.Errorf("baseURL: got %q", client.baseURL)
	}
	if client.retries != 3 {
		t.Errorf("retries: got %d, want 3", client.retries)
	}
	if client.backoff != 500*time.Millisecond {
		t.Errorf("backoff: got %v, want 500ms", client.backoff)
	}
	if client.base.Timeout != 30*time.Second {
		t.Errorf("timeout: got %v, want 30s", client.base.Timeout)
	}
	if client.authHeader != "" {
		t.Errorf("authHeader: got %q, want empty", client.authHeader)
	}
}
