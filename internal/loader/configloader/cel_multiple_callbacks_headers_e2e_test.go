package configloader

import (
	"net/http"
	"testing"
)

// TestCELMultipleCallbacksHeaders_E2E tests multiple CEL callbacks in on_request
func TestCELMultipleCallbacksHeaders_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "cel-multi-cb.test",
		"action":   map[string]any{"type": "echo"},
		"on_request": []map[string]any{
			{
				"cel_expr":      `{"first": "callback-1"}`,
				"variable_name": "cb_first",
			},
			{
				"cel_expr":      `{"second": "callback-2"}`,
				"variable_name": "cb_second",
			},
		},
	})

	r := newTestRequest(t, "GET", "http://cel-multi-cb.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
