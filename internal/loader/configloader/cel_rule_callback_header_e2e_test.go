package configloader

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestCELRuleCallbackHeader_E2E tests CEL rule-based callback that sets header data
func TestCELRuleCallbackHeader_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "cel-rule-hdr.test",
		"action":   map[string]any{"type": "echo"},
		"on_request": []map[string]any{
			{
				"cel_expr":      `{"rule_match": "true", "action": "allow"}`,
				"variable_name": "rule_result",
			},
		},
	})

	r := newTestRequest(t, "GET", "http://cel-rule-hdr.test/api/data")
	r.Header.Set("Authorization", "Bearer test-token")
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
