package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClientFederation(t *testing.T) {
	cfg := ClientFederationConfig{
		Servers: []ClientMCPServerConfig{
			{Name: "server1", URL: "http://localhost:8080"},
			{Name: "server2", URL: "http://localhost:8081"},
		},
	}

	fed := NewClientFederation(cfg)
	if fed == nil {
		t.Fatal("expected non-nil federation")
	}
	if fed.ServerCount() != 2 {
		t.Errorf("expected 2 servers, got %d", fed.ServerCount())
	}
}

func TestNewClientFederation_Empty(t *testing.T) {
	fed := NewClientFederation(ClientFederationConfig{})
	if fed == nil {
		t.Fatal("expected non-nil federation")
	}
	if fed.ServerCount() != 0 {
		t.Errorf("expected 0 servers, got %d", fed.ServerCount())
	}
}

func TestClientFederation_ListTools_Empty(t *testing.T) {
	fed := NewClientFederation(ClientFederationConfig{})
	tools := fed.ListTools()
	if len(tools) != 0 {
		t.Errorf("expected 0 tools, got %d", len(tools))
	}
}

func TestClientFederation_DiscoverTools(t *testing.T) {
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      1,
			Result: map[string]interface{}{
				"tools": []interface{}{
					map[string]interface{}{
						"name":        "search",
						"description": "Search things",
						"inputSchema": map[string]interface{}{"type": "object"},
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      1,
			Result: map[string]interface{}{
				"tools": []interface{}{
					map[string]interface{}{
						"name":        "lookup",
						"description": "Lookup by ID",
						"inputSchema": map[string]interface{}{"type": "object"},
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server2.Close()

	cfg := ClientFederationConfig{
		Servers: []ClientMCPServerConfig{
			{Name: "svc1", URL: server1.URL},
			{Name: "svc2", URL: server2.URL},
		},
	}

	fed := NewClientFederation(cfg)

	tools, err := fed.DiscoverTools(context.Background())
	if err != nil {
		t.Fatalf("DiscoverTools failed: %v", err)
	}

	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}

	// Verify tools are stored.
	stored := fed.ListTools()
	if len(stored) != 2 {
		t.Errorf("expected 2 stored tools, got %d", len(stored))
	}
}

func TestClientFederation_DiscoverTools_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := ClientFederationConfig{
		Servers: []ClientMCPServerConfig{
			{Name: "failing", URL: server.URL},
		},
	}

	fed := NewClientFederation(cfg)

	_, err := fed.DiscoverTools(context.Background())
	if err == nil {
		t.Fatal("expected error from failing server")
	}
}

func TestClientFederation_CallTool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		json.NewDecoder(r.Body).Decode(&req)

		if req.Method == "tools/list" {
			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: map[string]interface{}{
					"tools": []interface{}{
						map[string]interface{}{
							"name":        "greet",
							"description": "Greets a user",
							"inputSchema": map[string]interface{}{"type": "object"},
						},
					},
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}

		if req.Method == "tools/call" {
			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: map[string]interface{}{
					"content": []interface{}{
						map[string]interface{}{"type": "text", "text": "Hello!"},
					},
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
	}))
	defer server.Close()

	cfg := ClientFederationConfig{
		Servers: []ClientMCPServerConfig{
			{Name: "greeter", URL: server.URL},
		},
	}

	fed := NewClientFederation(cfg)

	// First discover tools.
	_, err := fed.DiscoverTools(context.Background())
	if err != nil {
		t.Fatalf("DiscoverTools failed: %v", err)
	}

	// Call the discovered tool.
	args, _ := json.Marshal(map[string]string{"name": "world"})
	result, err := fed.CallTool(context.Background(), "greet", args)
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestClientFederation_CallTool_NotFound(t *testing.T) {
	fed := NewClientFederation(ClientFederationConfig{})

	_, err := fed.CallTool(context.Background(), "nonexistent", nil)
	if err == nil {
		t.Fatal("expected error for nonexistent tool")
	}
}
