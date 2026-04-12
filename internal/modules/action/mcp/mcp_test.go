package mcp_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	mcpmod "github.com/soapbucket/sbproxy/internal/modules/action/mcp"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func TestNew_ValidConfig(t *testing.T) {
	raw := json.RawMessage(`{"server_info":{"name":"test-mcp","version":"1.0.0"}}`)
	h, err := mcpmod.New(raw)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if h == nil {
		t.Fatal("expected handler, got nil")
	}
}

func TestNew_InvalidJSON(t *testing.T) {
	_, err := mcpmod.New(json.RawMessage(`{bad`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestNew_DefaultServerInfo(t *testing.T) {
	// When server_info name is empty, the handler should default it.
	h, err := mcpmod.New(json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if h == nil {
		t.Fatal("expected handler, got nil")
	}
}

func TestType(t *testing.T) {
	h, _ := mcpmod.New(json.RawMessage(`{"server_info":{"name":"test","version":"1.0.0"}}`))
	if h.Type() != "mcp" {
		t.Errorf("Type() = %q, want %q", h.Type(), "mcp")
	}
}

func TestServeHTTP_WithoutProvision(t *testing.T) {
	// Without calling Provision, handler/gatewayHandler are nil.
	h, _ := mcpmod.New(json.RawMessage(`{"server_info":{"name":"test","version":"1.0.0"}}`))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d (handler not initialized)", rec.Code, http.StatusInternalServerError)
	}
}

func TestModuleRegistered(t *testing.T) {
	_, ok := plugin.GetAction("mcp")
	if !ok {
		t.Error("mcp action not registered in plugin registry")
	}
}
