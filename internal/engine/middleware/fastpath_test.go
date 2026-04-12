package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// BenchmarkFastPath_NoMetadataAccess measures the cost of FastPath when no
// downstream handler inspects the captured original request metadata.
// With lazy evaluation, header cloning and URL string building are skipped entirely.
func BenchmarkFastPath_NoMetadataAccess(b *testing.B) {
	handler := FastPathMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simple proxy-through: no metadata access
		w.WriteHeader(http.StatusOK)
	}))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "https://example.com/api/v1/users?page=1&limit=50", nil)
		req.Header.Set("Authorization", "Bearer tok123")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-Custom-Header", "value")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}
}

// BenchmarkFastPath_WithHeaderAccess measures the cost when a downstream handler
// actually reads the captured headers (triggering the lazy clone).
func BenchmarkFastPath_WithHeaderAccess(b *testing.B) {
	handler := FastPathMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rd := reqctx.GetRequestData(r.Context())
		if rd != nil && rd.OriginalRequest != nil {
			_ = rd.OriginalRequest.GetHeaders()
			_ = rd.OriginalRequest.GetURL()
		}
		w.WriteHeader(http.StatusOK)
	}))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "https://example.com/api/v1/users?page=1&limit=50", nil)
		req.Header.Set("Authorization", "Bearer tok123")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-Custom-Header", "value")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}
}

func TestFastPathMiddleware_CapturesBodyLazilyWhenRead(t *testing.T) {
	body := `{"hello":"world"}`
	handler := FastPathMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		if string(data) != body {
			t.Fatalf("expected request body %q, got %q", body, string(data))
		}

		rd := reqctx.GetRequestData(r.Context())
		if rd == nil || rd.OriginalRequest == nil {
			t.Fatal("expected original request data to be present")
		}
		if got := string(rd.OriginalRequest.Body); got != body {
			t.Fatalf("expected captured original body %q, got %q", body, got)
		}
		if bodyJSON := rd.OriginalRequest.BodyAsJSON(); bodyJSON == nil {
			t.Fatal("expected captured body to parse as JSON")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "https://example.com/test", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
}

func TestFastPathMiddleware_DoesNotCaptureUnreadBody(t *testing.T) {
	body := "unread body"
	handler := FastPathMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rd := reqctx.GetRequestData(r.Context())
		if rd == nil || rd.OriginalRequest == nil {
			t.Fatal("expected original request data to be present")
		}
		if len(rd.OriginalRequest.Body) != 0 {
			t.Fatalf("expected unread body to remain uncaptured, got %q", string(rd.OriginalRequest.Body))
		}
		w.WriteHeader(http.StatusAccepted)
	}))

	req := httptest.NewRequest(http.MethodPost, "https://example.com/test", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rr.Code)
	}
}
