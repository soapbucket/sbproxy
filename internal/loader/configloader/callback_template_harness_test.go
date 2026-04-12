package configloader

import (
	"net/http"
	"testing"
)

// TestCallbackTemplateVariables_OnLoad tests on_request callback with CEL template variable resolution
func TestCallbackTemplateVariables_OnLoad(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "cb-tpl-onload.test",
		"action":   map[string]any{"type": "echo"},
		"on_request": []map[string]any{
			{
				"cel_expr":      `{"loaded": "true"}`,
				"variable_name": "onload_vars",
			},
		},
	})

	r := newTestRequest(t, "GET", "http://cb-tpl-onload.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestCallbackTemplateVariables_Session tests session-aware callback template variables.
// Without a SessionProvider, session data is empty but the request should still succeed.
func TestCallbackTemplateVariables_Session(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "cb-tpl-session.test",
		"action":   map[string]any{"type": "echo"},
		"on_request": []map[string]any{
			{
				"cel_expr":      `{"session_checked": "true"}`,
				"variable_name": "session_vars",
			},
		},
	})

	r := newTestRequest(t, "GET", "http://cb-tpl-session.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestCallbackTemplateVariables_Auth tests auth-aware callback with CEL
func TestCallbackTemplateVariables_Auth(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "cb-tpl-auth.test",
		"action":   map[string]any{"type": "echo"},
		"authentication": map[string]any{
			"type":     "api_key",
			"api_keys": []string{"test-key"},
		},
		"on_request": []map[string]any{
			{
				"cel_expr":      `{"auth_checked": "true"}`,
				"variable_name": "auth_vars",
			},
		},
	})

	r := newTestRequest(t, "GET", "http://cb-tpl-auth.test/")
	r.Header.Set("X-API-Key", "test-key")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
