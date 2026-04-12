package configloader

import (
	"net/http"
	"strings"
	"testing"
)

// TestErrorPageCallback500_E2E tests error page rendering on 500 errors
func TestErrorPageCallback500_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "errorpage500.test",
		"action": map[string]any{
			"type":        "mock",
			"status_code": 500,
			"body":        "Internal Server Error",
		},
		"error_pages": []map[string]any{
			{
				"status":       []int{500},
				"body":         "<h1>Custom 500</h1><p>Something went wrong</p>",
				"content_type": "text/html",
			},
		},
	})

	r := newTestRequest(t, "GET", "http://errorpage500.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Custom 500") {
		t.Fatalf("expected custom error page body, got: %s", w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html" {
		t.Fatalf("expected Content-Type text/html, got %q", ct)
	}
}
