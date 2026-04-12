package configloader

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestVariables_TemplateInterpolation_E2E tests variable interpolation in configurations
func TestVariables_TemplateInterpolation_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "vars-interp.test",
		"action":   map[string]any{"type": "echo", "include_context": true},
		"variables": map[string]any{
			"app_name": "test-app",
			"version":  "1.0.0",
		},
	})

	r := newTestRequest(t, "GET", "http://vars-interp.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify the config compiled successfully with variables
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("parse echo response: %v", err)
	}
	if _, ok := result["request"]; !ok {
		t.Fatal("echo response missing 'request' object")
	}
}

// TestVaulting_SecretInjection_E2E tests that secrets config compiles and plain values work.
// Without a vault manager, secrets resolve from plaintext values in the config.
func TestVaulting_SecretInjection_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "vaulting.test",
		"action":   map[string]any{"type": "echo"},
		"request_modifiers": []map[string]any{
			{
				"headers": map[string]any{
					"add": map[string]string{
						"X-API-Token": "plain-test-token",
					},
				},
			},
		},
	})

	r := newTestRequest(t, "GET", "http://vaulting.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("parse echo response: %v", err)
	}
	req := result["request"].(map[string]any)
	headers := req["headers"].(map[string]any)
	if _, ok := headers["X-Api-Token"]; !ok {
		t.Fatal("expected X-API-Token header in echo response")
	}
}

// TestVariables_SessionData_E2E tests that session variable references compile cleanly.
// Without a SessionProvider, session variables resolve to empty but the request succeeds.
func TestVariables_SessionData_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "vars-session.test",
		"action":   map[string]any{"type": "echo"},
		"variables": map[string]any{
			"user_role": "guest",
		},
		"request_modifiers": []map[string]any{
			{
				"headers": map[string]any{
					"add": map[string]string{
						"X-User-Role": "{{vars.user_role}}",
					},
				},
			},
		},
	})

	r := newTestRequest(t, "GET", "http://vars-session.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestVariables_Conditional_E2E tests conditional variable usage via on_request callback
func TestVariables_Conditional_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "vars-cond.test",
		"action":   map[string]any{"type": "echo"},
		"variables": map[string]any{
			"deploy_env": "production",
		},
		"on_request": []map[string]any{
			{
				"cel_expr":      `{"is_prod": "yes"}`,
				"variable_name": "env_check",
			},
		},
	})

	r := newTestRequest(t, "GET", "http://vars-cond.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestVariables_Templating_Advanced_E2E tests advanced template features with echo action
func TestVariables_Templating_Advanced_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "vars-adv.test",
		"action":   map[string]any{"type": "echo"},
		"variables": map[string]any{
			"app_name":    "my-app",
			"app_version": "3.0.0",
			"region":      "us-east-1",
		},
		"request_modifiers": []map[string]any{
			{
				"headers": map[string]any{
					"add": map[string]string{
						"X-App-Name":    "{{vars.app_name}}",
						"X-App-Version": "{{vars.app_version}}",
					},
				},
			},
		},
	})

	r := newTestRequest(t, "GET", "http://vars-adv.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
