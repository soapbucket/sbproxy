package configloader

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestRequestModifiersHeader_TemplateVariables tests request modifiers with template variables
func TestRequestModifiersHeader_TemplateVariables(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "reqmod-tpl.test",
		"action":   map[string]any{"type": "echo"},
		"request_modifiers": []map[string]any{
			{
				"headers": map[string]any{
					"add": map[string]string{
						"X-Static-Header": "static-value",
					},
				},
			},
		},
	})

	r := newTestRequest(t, "GET", "http://reqmod-tpl.test/")
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
	if _, ok := headers["X-Static-Header"]; !ok {
		t.Fatal("expected X-Static-Header in echo response headers")
	}
}

// TestResponseModifiersHeader tests response modifiers setting headers
func TestResponseModifiersHeader(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "respmod-hdr.test",
		"action":   map[string]any{"type": "echo"},
		"response_modifiers": []map[string]any{
			{
				"headers": map[string]any{
					"add": map[string]string{
						"X-Response-Custom": "custom-value",
					},
				},
			},
		},
	})

	r := newTestRequest(t, "GET", "http://respmod-hdr.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Response-Custom") != "custom-value" {
		t.Fatalf("expected X-Response-Custom: custom-value, got %q", w.Header().Get("X-Response-Custom"))
	}
}
