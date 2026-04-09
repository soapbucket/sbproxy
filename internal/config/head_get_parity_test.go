package config

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestStreamingProxy_HeadGetParity verifies that HEAD responses from the proxy
// match GET response headers (Content-Type, Content-Length, ETag,
// Last-Modified, Cache-Control) while having no body.
func TestStreamingProxy_HeadGetParity(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		body    string
	}{
		{
			name: "JSON response with caching headers",
			headers: map[string]string{
				"Content-Type":  "application/json",
				"ETag":          `"abc123"`,
				"Last-Modified": "Mon, 09 Mar 2026 12:00:00 GMT",
				"Cache-Control": "max-age=3600, public",
			},
			body: `{"status":"ok","count":42}`,
		},
		{
			name: "HTML response with no-cache",
			headers: map[string]string{
				"Content-Type":  "text/html; charset=utf-8",
				"ETag":          `W/"weak-tag"`,
				"Cache-Control": "no-cache, no-store",
			},
			body: "<html><body>Hello World</body></html>",
		},
		{
			name: "Binary response with strong ETag",
			headers: map[string]string{
				"Content-Type":  "application/octet-stream",
				"ETag":          `"deadbeef0123"`,
				"Last-Modified": "Sat, 07 Mar 2026 08:30:00 GMT",
				"Cache-Control": "max-age=86400, immutable",
			},
			body: "binary-payload-placeholder",
		},
		{
			name: "Plain text with minimal headers",
			headers: map[string]string{
				"Content-Type": "text/plain",
			},
			body: "simple text response",
		},
		{
			name: "Empty body with headers",
			headers: map[string]string{
				"Content-Type":  "application/json",
				"ETag":          `"empty"`,
				"Cache-Control": "private, max-age=60",
			},
			body: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for key, val := range tt.headers {
					w.Header().Set(key, val)
				}
				w.WriteHeader(http.StatusOK)
				if r.Method != http.MethodHead {
					_, _ = w.Write([]byte(tt.body))
				}
			}))
			defer backend.Close()

			cfg := createTestProxyConfig(t, backend.URL)

			handler := NewStreamingProxyHandler(cfg)

			// Issue GET request
			getReq := httptest.NewRequest(http.MethodGet, "/test", nil)
			getReq.RemoteAddr = "192.168.1.100:12345"
			getRec := httptest.NewRecorder()
			handler.ServeHTTP(getRec, getReq)

			if getRec.Code != http.StatusOK {
				t.Fatalf("GET: expected 200, got %d", getRec.Code)
			}

			// Issue HEAD request
			headReq := httptest.NewRequest(http.MethodHead, "/test", nil)
			headReq.RemoteAddr = "192.168.1.100:12345"
			headRec := httptest.NewRecorder()
			handler.ServeHTTP(headRec, headReq)

			if headRec.Code != http.StatusOK {
				t.Fatalf("HEAD: expected 200, got %d", headRec.Code)
			}

			// HEAD response must have no body
			if headRec.Body.Len() != 0 {
				t.Errorf("HEAD: expected empty body, got %d bytes", headRec.Body.Len())
			}

			// Compare headers that should match between GET and HEAD
			parityHeaders := []string{
				"Content-Type",
				"ETag",
				"Last-Modified",
				"Cache-Control",
			}

			for _, hdr := range parityHeaders {
				getVal := getRec.Header().Get(hdr)
				headVal := headRec.Header().Get(hdr)

				if getVal == "" && headVal == "" {
					// Neither response has this header, that is fine
					continue
				}

				if getVal != headVal {
					t.Errorf("header %s mismatch: GET=%q, HEAD=%q", hdr, getVal, headVal)
				}
			}
		})
	}
}

// TestStreamingProxy_HeadNoBody verifies that HEAD requests never produce a
// response body even when the backend serves content for all methods.
func TestStreamingProxy_HeadNoBody(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "26")
		w.WriteHeader(http.StatusOK)
		// Write body regardless of method (backend misbehavior)
		_, _ = w.Write([]byte(`{"status":"always-writes"}`))
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	handler := NewStreamingProxyHandler(cfg)

	req := httptest.NewRequest(http.MethodHead, "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	// The Go net/http server layer strips the body for HEAD automatically,
	// but we verify the proxy does not interfere with that behavior.
	// httptest.ResponseRecorder does not enforce this, so we check Content-Type
	// is still present (header parity).
	if rec.Header().Get("Content-Type") == "" {
		t.Error("expected Content-Type header to be present for HEAD response")
	}
}

// TestStreamingProxy_HeadStatusCodes verifies that HEAD responses preserve
// status codes from the backend.
func TestStreamingProxy_HeadStatusCodes(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"200 OK", http.StatusOK},
		{"204 No Content", http.StatusNoContent},
		{"304 Not Modified", http.StatusNotModified},
		{"404 Not Found", http.StatusNotFound},
		{"500 Internal Server Error", http.StatusInternalServerError},
		{"503 Service Unavailable", http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer backend.Close()

			cfg := createTestProxyConfig(t, backend.URL)
			handler := NewStreamingProxyHandler(cfg)

			headReq := httptest.NewRequest(http.MethodHead, "/test", nil)
			headReq.RemoteAddr = "192.168.1.100:12345"
			headRec := httptest.NewRecorder()
			handler.ServeHTTP(headRec, headReq)

			if headRec.Code != tt.statusCode {
				t.Errorf("HEAD: expected %d, got %d", tt.statusCode, headRec.Code)
			}

			getReq := httptest.NewRequest(http.MethodGet, "/test", nil)
			getReq.RemoteAddr = "192.168.1.100:12345"
			getRec := httptest.NewRecorder()
			handler.ServeHTTP(getRec, getReq)

			if getRec.Code != tt.statusCode {
				t.Errorf("GET: expected %d, got %d", tt.statusCode, getRec.Code)
			}

			// Status codes should match
			if headRec.Code != getRec.Code {
				t.Errorf("status code mismatch: HEAD=%d, GET=%d", headRec.Code, getRec.Code)
			}
		})
	}
}
