package configloader

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestCELExpressionPolicyCallback tests CEL expression in on_request callback
// using the json variable that receives callback context
func TestCELExpressionPolicyCallback(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "cel-policy-cb.test",
		"action":   map[string]any{"type": "echo"},
		"on_request": []map[string]any{
			{
				"cel_expr":      `{"enriched": "true", "source": "cel_callback"}`,
				"variable_name": "cel_result",
			},
		},
	})

	r := newTestRequest(t, "GET", "http://cel-policy-cb.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("parse echo response: %v", err)
	}
	if _, ok := result["request"]; !ok {
		t.Fatal("echo response missing 'request' object")
	}
}
