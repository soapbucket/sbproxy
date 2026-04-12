package configloader

import (
	"net/http"
	"testing"
)

// TestHTMLTransformHN_405Error tests that HEAD requests are handled correctly with allowed_methods
func TestHTMLTransformHN_405Error(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname":        "hn-transform.test",
		"action":          map[string]any{"type": "echo"},
		"allowed_methods": []string{"GET", "HEAD"},
	})

	t.Run("GET allowed", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://hn-transform.test/")
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("HEAD allowed", func(t *testing.T) {
		r := newTestRequest(t, "HEAD", "http://hn-transform.test/")
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("POST rejected with 405", func(t *testing.T) {
		r := newTestRequest(t, "POST", "http://hn-transform.test/")
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", w.Code)
		}
	})
}
