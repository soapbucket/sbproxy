package configloader

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestCELCallbackHeaders_E2E tests CEL callback that produces header data via on_request
func TestCELCallbackHeaders_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "cel-cb-hdr.test",
		"action":   map[string]any{"type": "echo"},
		"on_request": []map[string]any{
			{
				"cel_expr":      `{"header_data": "from-cel"}`,
				"variable_name": "cel_headers",
			},
		},
	})

	r := newTestRequest(t, "GET", "http://cel-cb-hdr.test/")
	r.Header.Set("X-Test", "value")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("parse echo response: %v", err)
	}
	req, ok := result["request"].(map[string]any)
	if !ok {
		t.Fatal("echo response missing 'request' object")
	}
	headers, ok := req["headers"].(map[string]any)
	if !ok {
		t.Fatal("echo response missing 'headers' in request")
	}
	if _, ok := headers["X-Test"]; !ok {
		t.Fatal("expected X-Test header in echo response")
	}
}

// TestCELExpressionPolicyCallback_E2E tests CEL expression policy with on_request callback
func TestCELExpressionPolicyCallback_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "cel-expr-policy.test",
		"action":   map[string]any{"type": "echo"},
		"on_request": []map[string]any{
			{
				"cel_expr":      `{"computed": "value", "timestamp": "now"}`,
				"variable_name": "policy_data",
			},
		},
	})

	r := newTestRequest(t, "GET", "http://cel-expr-policy.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
