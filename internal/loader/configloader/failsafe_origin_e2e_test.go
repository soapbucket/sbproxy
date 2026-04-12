package configloader

import (
	"net/http"
	"testing"
)

// TestFailsafeOrigin_Hostname_E2E tests that an origin compiles and serves correctly
// even without a storage layer for snapshot persistence.
func TestFailsafeOrigin_Hostname_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "failsafe-host.test",
		"action": map[string]any{
			"type":        "mock",
			"status_code": 200,
			"body":        "failsafe hostname origin",
		},
	})

	r := newTestRequest(t, "GET", "http://failsafe-host.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestFailsafeOrigin_Embedded_E2E tests that an embedded origin compiles correctly
// without a storage layer.
func TestFailsafeOrigin_Embedded_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "failsafe-embed.test",
		"action": map[string]any{
			"type":        "mock",
			"status_code": 200,
			"body":        "failsafe embedded origin",
		},
	})

	r := newTestRequest(t, "GET", "http://failsafe-embed.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
