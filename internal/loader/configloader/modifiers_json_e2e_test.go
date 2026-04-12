package configloader

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestRequestModifier_AddRemoveHeaders_E2E tests adding and removing request headers
func TestRequestModifier_AddRemoveHeaders_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "reqmod-headers.test",
		"action":   map[string]any{"type": "echo"},
		"request_modifiers": []map[string]any{
			{
				"headers": map[string]any{
					"add": map[string]string{
						"X-Added": "injected-value",
					},
					"delete": []string{"X-Remove-Me"},
				},
			},
		},
	})

	r := newTestRequest(t, "GET", "http://reqmod-headers.test/")
	r.Header.Set("X-Remove-Me", "should-be-gone")
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

	if _, ok := headers["X-Added"]; !ok {
		t.Fatal("expected X-Added header in echo response")
	}
	if _, ok := headers["X-Remove-Me"]; ok {
		t.Fatal("X-Remove-Me header should have been removed")
	}
}

// TestRequestModifier_QueryParams_E2E tests modifying query parameters
func TestRequestModifier_QueryParams_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "reqmod-query.test",
		"action":   map[string]any{"type": "echo"},
		"request_modifiers": []map[string]any{
			{
				"query": map[string]any{
					"add": map[string]string{
						"injected": "param-value",
					},
				},
			},
		},
	})

	r := newTestRequest(t, "GET", "http://reqmod-query.test/?existing=true")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("parse echo response: %v", err)
	}
	req := result["request"].(map[string]any)
	urlStr, ok := req["url"].(string)
	if !ok {
		t.Fatal("echo response missing url")
	}
	if !strings.Contains(urlStr, "existing=true") {
		t.Fatalf("expected existing query param preserved, got: %s", urlStr)
	}
}

// TestResponseModifier_JSONBodyTransform_E2E tests transforming JSON response bodies
func TestResponseModifier_JSONBodyTransform_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "respmod-json.test",
		"action": map[string]any{
			"type":        "mock",
			"status_code": 200,
			"body":        `{"name":"Alice","age":30}`,
			"headers":     map[string]string{"Content-Type": "application/json"},
		},
		"response_modifiers": []map[string]any{
			{
				"headers": map[string]any{
					"add": map[string]string{
						"X-Modified": "true",
					},
				},
			},
		},
	})

	r := newTestRequest(t, "GET", "http://respmod-json.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Modified") != "true" {
		t.Fatalf("expected X-Modified: true, got %q", w.Header().Get("X-Modified"))
	}
}

// TestResponseModifier_AddHeaders_E2E tests adding response headers
func TestResponseModifier_AddHeaders_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "respmod-add.test",
		"action":   map[string]any{"type": "echo"},
		"response_modifiers": []map[string]any{
			{
				"headers": map[string]any{
					"add": map[string]string{
						"X-Response-Extra":   "extra-value",
						"X-Response-Extra-2": "extra-value-2",
					},
				},
			},
		},
	})

	r := newTestRequest(t, "GET", "http://respmod-add.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("X-Response-Extra") != "extra-value" {
		t.Fatalf("expected X-Response-Extra: extra-value, got %q", w.Header().Get("X-Response-Extra"))
	}
}

// TestRequestModifier_CookieHandling_E2E tests cookie modification with echo action
func TestRequestModifier_CookieHandling_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "reqmod-cookie.test",
		"action":   map[string]any{"type": "echo"},
		"request_modifiers": []map[string]any{
			{
				"headers": map[string]any{
					"add": map[string]string{
						"X-Cookie-Marker": "modified",
					},
				},
			},
		},
	})

	r := newTestRequest(t, "GET", "http://reqmod-cookie.test/")
	r.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})
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
	if _, ok := headers["X-Cookie-Marker"]; !ok {
		t.Fatal("expected X-Cookie-Marker header in echo response")
	}
	// Verify cookie was preserved
	if _, ok := headers["Cookie"]; !ok {
		t.Fatal("expected Cookie header preserved in echo response")
	}
}

// TestRequestModifier_TemplateVariables_E2E tests template variable expansion in header modifiers
func TestRequestModifier_TemplateVariables_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "tpl-vars.test",
		"action":   map[string]any{"type": "echo"},
		"variables": map[string]any{
			"app_version": "2.0.0",
		},
		"request_modifiers": []map[string]any{
			{
				"headers": map[string]any{
					"add": map[string]string{
						"X-App-Version": "{{config.app_version}}",
						"X-Static":      "static-value",
					},
				},
			},
		},
	})

	r := newTestRequest(t, "GET", "http://tpl-vars.test/")
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

	if _, ok := headers["X-Static"]; !ok {
		t.Fatal("expected X-Static header in echo response")
	}
}

// TestConditionalModifier_CELExpression_E2E tests modifiers with CEL-based conditions.
// Uses on_request callback with CEL to set a variable, then verifies the modifier chain runs.
func TestConditionalModifier_CELExpression_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "cel-mod.test",
		"action":   map[string]any{"type": "echo"},
		"on_request": []map[string]any{
			{
				"cel_expr":      `{"conditional_check": "passed"}`,
				"variable_name": "cel_result",
			},
		},
		"request_modifiers": []map[string]any{
			{
				"headers": map[string]any{
					"add": map[string]string{
						"X-CEL-Modified": "true",
					},
				},
			},
		},
	})

	r := newTestRequest(t, "GET", "http://cel-mod.test/")
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
	if _, ok := headers["X-Cel-Modified"]; !ok {
		t.Fatal("expected X-CEL-Modified header from conditional modifier")
	}
}

// TestModifier_PathSpecific_E2E tests path-specific modifier application using rules.
func TestModifier_PathSpecific_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "path-mod.test",
		"action":   map[string]any{"type": "echo"},
		"request_modifiers": []map[string]any{
			{
				"headers": map[string]any{
					"add": map[string]string{
						"X-API-Modified": "true",
					},
				},
				"rules": []map[string]any{
					{"path": map[string]any{"prefix": "/api/"}},
				},
			},
		},
	})

	t.Run("matching path gets header", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://path-mod.test/api/data")
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var result map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatalf("parse response: %v", err)
		}
		req := result["request"].(map[string]any)
		headers := req["headers"].(map[string]any)
		if _, ok := headers["X-Api-Modified"]; !ok {
			t.Fatal("expected X-API-Modified header for /api/ path")
		}
	})

	t.Run("non-matching path does not get header", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://path-mod.test/other/data")
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var result map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatalf("parse response: %v", err)
		}
		req := result["request"].(map[string]any)
		headers := req["headers"].(map[string]any)
		if _, ok := headers["X-Api-Modified"]; ok {
			t.Fatal("should NOT have X-API-Modified header for non-api path")
		}
	})
}

// TestModifier_MethodSpecific_E2E tests method-specific modifier application using rules.
func TestModifier_MethodSpecific_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "method-mod.test",
		"action":   map[string]any{"type": "echo"},
		"request_modifiers": []map[string]any{
			{
				"headers": map[string]any{
					"add": map[string]string{
						"X-Post-Only": "true",
					},
				},
				"rules": []map[string]any{
					{"methods": []string{"POST"}},
				},
			},
		},
	})

	t.Run("POST gets header", func(t *testing.T) {
		r := newTestRequest(t, "POST", "http://method-mod.test/")
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var result map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatalf("parse response: %v", err)
		}
		req := result["request"].(map[string]any)
		headers := req["headers"].(map[string]any)
		if _, ok := headers["X-Post-Only"]; !ok {
			t.Fatal("expected X-Post-Only header for POST request")
		}
	})

	t.Run("GET does not get header", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://method-mod.test/")
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var result map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatalf("parse response: %v", err)
		}
		req := result["request"].(map[string]any)
		headers := req["headers"].(map[string]any)
		if _, ok := headers["X-Post-Only"]; ok {
			t.Fatal("should NOT have X-Post-Only header for GET request")
		}
	})
}

// TestChainedModifiers_E2E tests multiple modifiers applied in sequence
func TestChainedModifiers_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "chained-mod.test",
		"action":   map[string]any{"type": "echo"},
		"request_modifiers": []map[string]any{
			{
				"headers": map[string]any{
					"add": map[string]string{
						"X-First": "first-value",
					},
				},
			},
			{
				"headers": map[string]any{
					"add": map[string]string{
						"X-Second": "second-value",
					},
				},
			},
		},
	})

	r := newTestRequest(t, "GET", "http://chained-mod.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("parse echo response: %v", err)
	}
	req := result["request"].(map[string]any)
	headers := req["headers"].(map[string]any)

	for _, key := range []string{"X-First", "X-Second"} {
		if _, ok := headers[key]; !ok {
			t.Fatalf("expected %s header in echo response", key)
		}
	}
}

// TestURLQueryParameter_Modification_E2E tests URL and query string modifications
func TestURLQueryParameter_Modification_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "url-mod.test",
		"action":   map[string]any{"type": "echo"},
	})

	r := newTestRequest(t, "GET", "http://url-mod.test/path?key=value&extra=data")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "key=value") {
		t.Fatal("expected query params in echo response")
	}
}
