package configloader

import (
	"net/http"
	"testing"
)

// TestCELCallbackConfigHeader_E2E tests CEL callback config-driven header enrichment
func TestCELCallbackConfigHeader_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "cel-cfg-hdr.test",
		"action":   map[string]any{"type": "echo"},
		"on_request": []map[string]any{
			{
				"cel_expr":      `{"config_key": "test-config-value"}`,
				"variable_name": "config_header_data",
			},
		},
	})

	r := newTestRequest(t, "GET", "http://cel-cfg-hdr.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
