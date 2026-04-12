package echo_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	echomod "github.com/soapbucket/sbproxy/internal/modules/action/echo"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

// TestNew_ParsesConfig verifies that New correctly parses JSON configuration.
func TestNew_ParsesConfig(t *testing.T) {
	tests := []struct {
		name           string
		raw            string
		wantIncludeCtx bool
		wantErr        bool
	}{
		{
			name:           "basic echo config",
			raw:            `{"type":"echo"}`,
			wantIncludeCtx: false,
		},
		{
			name:           "include_context true",
			raw:            `{"type":"echo","include_context":true}`,
			wantIncludeCtx: true,
		},
		{
			name:    "invalid JSON",
			raw:     `{not valid json`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := echomod.New(json.RawMessage(tt.raw))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if h == nil {
				t.Fatal("expected handler but got nil")
			}
			if h.Type() != "echo" {
				t.Errorf("Type() = %q, want %q", h.Type(), "echo")
			}
		})
	}
}

// TestServeHTTP_BasicRequest verifies the handler returns correct JSON for a GET.
func TestServeHTTP_BasicRequest(t *testing.T) {
	h, err := echomod.New(json.RawMessage(`{"type":"echo"}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/foo?bar=1", nil)
	req.Header.Set("X-Custom", "hello")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if _, ok := payload["timestamp"]; !ok {
		t.Error("response missing 'timestamp'")
	}

	reqInfo, ok := payload["request"].(map[string]any)
	if !ok {
		t.Fatal("response missing 'request' object")
	}
	if reqInfo["method"] != http.MethodGet {
		t.Errorf("method = %v, want GET", reqInfo["method"])
	}
	if reqInfo["url"] != "http://example.com/foo?bar=1" {
		t.Errorf("url = %v", reqInfo["url"])
	}
}

// TestServeHTTP_WithBody verifies the request body is included in the response.
func TestServeHTTP_WithBody(t *testing.T) {
	h, err := echomod.New(json.RawMessage(`{"type":"echo"}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	body := `{"hello":"world"}`
	req := httptest.NewRequest(http.MethodPost, "http://example.com/api", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	reqInfo := payload["request"].(map[string]any)
	if reqInfo["body"] != body {
		t.Errorf("body = %v, want %q", reqInfo["body"], body)
	}
}

// TestServeHTTP_IncludeContext verifies the context block appears when configured.
func TestServeHTTP_IncludeContext(t *testing.T) {
	h, err := echomod.New(json.RawMessage(`{"type":"echo","include_context":true}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Provision it with a known context.
	p, ok := h.(plugin.Provisioner)
	if !ok {
		t.Fatal("handler does not implement plugin.Provisioner")
	}
	if err := p.Provision(plugin.PluginContext{
		OriginID:    "orig-123",
		WorkspaceID: "ws-456",
	}); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	ctx, ok := payload["context"].(map[string]any)
	if !ok {
		t.Fatal("response missing 'context' when include_context=true")
	}
	if ctx["origin_id"] != "orig-123" {
		t.Errorf("context.origin_id = %v, want orig-123", ctx["origin_id"])
	}
	if ctx["workspace_id"] != "ws-456" {
		t.Errorf("context.workspace_id = %v, want ws-456", ctx["workspace_id"])
	}
}

// TestServeHTTP_NoContextBlock verifies "context" is absent when include_context=false.
func TestServeHTTP_NoContextBlock(t *testing.T) {
	h, err := echomod.New(json.RawMessage(`{"type":"echo"}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := payload["context"]; ok {
		t.Error("response should NOT contain 'context' when include_context=false")
	}
}

// TestModuleRegistered verifies that the echo init() registered the factory
// in the global pkg/plugin registry.
func TestModuleRegistered(t *testing.T) {
	_, ok := plugin.GetAction("echo")
	if !ok {
		t.Error("echo action not found in plugin registry; init() may not have run")
	}
}

// TestValidate verifies that Validate returns nil for all valid configs.
func TestValidate(t *testing.T) {
	h, err := echomod.New(json.RawMessage(`{"type":"echo","include_context":true}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v, ok := h.(plugin.Validator)
	if !ok {
		t.Fatal("handler does not implement plugin.Validator")
	}
	if err := v.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

// TestServeHTTP_NoBody verifies body is absent in response when request has no body.
func TestServeHTTP_NoBody(t *testing.T) {
	h, err := echomod.New(json.RawMessage(`{"type":"echo"}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	reqInfo := payload["request"].(map[string]any)
	if _, ok := reqInfo["body"]; ok {
		t.Error("response should NOT contain 'body' when request body is empty")
	}
}

// TestContentLengthHeader verifies Content-Length is present and numeric.
func TestContentLengthHeader(t *testing.T) {
	h, err := echomod.New(json.RawMessage(`{"type":"echo"}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	clHeader := rec.Header().Get("Content-Length")
	if clHeader == "" {
		t.Fatal("missing Content-Length header")
	}

	cl, err := strconv.Atoi(clHeader)
	if err != nil {
		t.Errorf("Content-Length %q is not a number: %v", clHeader, err)
	}
	if cl != rec.Body.Len() {
		t.Errorf("Content-Length %d != actual body length %d", cl, rec.Body.Len())
	}
}
