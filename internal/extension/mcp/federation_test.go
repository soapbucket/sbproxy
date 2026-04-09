package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFederatedTool_QualifiedName(t *testing.T) {
	// QualifiedName now returns the Name directly since names are resolved during discovery
	tests := []struct {
		name     string
		tool     FederatedTool
		expected string
	}{
		{
			name:     "pre-resolved prefixed name",
			tool:     FederatedTool{Name: "github_search", Prefix: "github"},
			expected: "github_search",
		},
		{
			name:     "without prefix",
			tool:     FederatedTool{Name: "search"},
			expected: "search",
		},
		{
			name:     "renamed tool",
			tool:     FederatedTool{Name: "find_stuff", Prefix: "svc"},
			expected: "find_stuff",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tool.QualifiedName()
			if got != tt.expected {
				t.Errorf("QualifiedName() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestNewFederation(t *testing.T) {
	servers := []FederatedServerConfig{
		{URL: "http://localhost:8080", Prefix: "svc1"},
	}
	fed := NewFederation(servers)
	if fed == nil {
		t.Fatal("expected non-nil Federation")
	}
	if len(fed.servers) != 1 {
		t.Errorf("expected 1 server, got %d", len(fed.servers))
	}
	if len(fed.tools) != 0 {
		t.Errorf("expected 0 tools initially, got %d", len(fed.tools))
	}
}

func TestFederation_GetTool_Empty(t *testing.T) {
	fed := NewFederation(nil)
	tool, ok := fed.GetTool("anything")
	if ok || tool != nil {
		t.Error("expected no tool found on empty federation")
	}
}

func TestFederation_ListTools_Empty(t *testing.T) {
	fed := NewFederation(nil)
	tools := fed.ListTools()
	if len(tools) != 0 {
		t.Errorf("expected 0 tools, got %d", len(tools))
	}
}

func TestFederation_DiscoverTools(t *testing.T) {
	// Create a mock MCP server that returns tools
	mockTools := ListToolsResult{
		Tools: []Tool{
			{
				Name:        "search",
				Description: "Search things",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}}}`),
			},
			{
				Name:        "lookup",
				Description: "Lookup by ID",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"id":{"type":"string"}}}`),
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      1,
			Result:  &mockTools,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	fed := NewFederation([]FederatedServerConfig{
		{URL: server.URL, Prefix: "svc"},
	})

	if err := fed.DiscoverTools(context.Background()); err != nil {
		t.Fatalf("DiscoverTools failed: %v", err)
	}

	tools := fed.ListTools()
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}

	// Check prefixed lookup - names are now resolved during discovery
	tool, ok := fed.GetTool("svc_search")
	if !ok {
		t.Fatal("expected to find svc_search")
	}
	if tool.Name != "svc_search" {
		t.Errorf("expected resolved name 'svc_search', got %q", tool.Name)
	}
	if tool.Server != server.URL {
		t.Errorf("expected server URL %q, got %q", server.URL, tool.Server)
	}

	// Non-existent tool
	_, ok = fed.GetTool("nonexistent")
	if ok {
		t.Error("expected not found for nonexistent tool")
	}
}

func TestFederation_DiscoverTools_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	fed := NewFederation([]FederatedServerConfig{
		{URL: server.URL, Prefix: "bad"},
	})

	err := fed.DiscoverTools(context.Background())
	if err == nil {
		t.Fatal("expected error from failing server")
	}
}

func TestFederation_DiscoverTools_NoPrefixCollision(t *testing.T) {
	mockTools := ListToolsResult{
		Tools: []Tool{
			{Name: "query", Description: "Query tool", InputSchema: json.RawMessage(`{"type":"object"}`)},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := JSONRPCResponse{JSONRPC: "2.0", ID: 1, Result: &mockTools}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	fed := NewFederation([]FederatedServerConfig{
		{URL: server.URL}, // No prefix
	})

	if err := fed.DiscoverTools(context.Background()); err != nil {
		t.Fatalf("DiscoverTools failed: %v", err)
	}

	tool, ok := fed.GetTool("query")
	if !ok {
		t.Fatal("expected to find 'query' (no prefix)")
	}
	if tool.Prefix != "" {
		t.Errorf("expected empty prefix, got %q", tool.Prefix)
	}
}

func TestFederation_DiscoverTools_InvalidTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"result": map[string]interface{}{"tools": []interface{}{}}})
	}))
	defer server.Close()

	fed := NewFederation([]FederatedServerConfig{
		{URL: server.URL, Timeout: "not-a-duration"},
	})

	err := fed.DiscoverTools(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid timeout")
	}
}
