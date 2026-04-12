package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// =============================================================================
// P1: Error Mapping
// =============================================================================

func TestErrorMapping_ExactCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"not found"}`))
	}))
	defer server.Close()

	config := &Config{
		Tools: []ToolConfig{
			{
				Name: "err_tool",
				Handler: ToolHandler{
					Type: "proxy",
					Proxy: &ProxyHandler{
						URL: server.URL,
						ErrorMapping: map[string]string{
							"404": "The item was not found.",
							"500": "Server error occurred.",
						},
					},
				},
			},
		},
	}

	registry := NewToolRegistry()
	for _, tool := range config.Tools {
		registry.Register(tool)
	}
	validator, _ := NewSchemaValidator(config.Tools)
	executor := NewToolExecutor(registry, validator, config)

	_, err := executor.Execute(context.Background(), "err_tool", nil)
	if err == nil {
		t.Fatal("Expected error")
	}

	// Error should contain the mapped message, not raw HTTP error
	if err.Message != "The item was not found." {
		t.Errorf("Expected mapped error message, got: %s", err.Message)
	}

	// Should be a tool execution error (isError: true), not protocol error
	if err.Type != ErrorTypeToolExecution {
		t.Errorf("Expected tool execution error type, got: %s", err.Type)
	}
}

func TestErrorMapping_WildcardRange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway) // 502
		w.Write([]byte("upstream error"))
	}))
	defer server.Close()

	config := &Config{
		Tools: []ToolConfig{
			{
				Name: "err_tool",
				Handler: ToolHandler{
					Type: "proxy",
					Proxy: &ProxyHandler{
						URL: server.URL,
						ErrorMapping: map[string]string{
							"5xx": "The service is temporarily unavailable.",
						},
					},
				},
			},
		},
	}

	registry := NewToolRegistry()
	for _, tool := range config.Tools {
		registry.Register(tool)
	}
	validator, _ := NewSchemaValidator(config.Tools)
	executor := NewToolExecutor(registry, validator, config)

	_, err := executor.Execute(context.Background(), "err_tool", nil)
	if err == nil {
		t.Fatal("Expected error")
	}

	if err.Message != "The service is temporarily unavailable." {
		t.Errorf("Expected wildcard mapped error, got: %s", err.Message)
	}
}

func TestErrorMapping_NoMatch_FallsThrough(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden) // 403
		w.Write([]byte("forbidden"))
	}))
	defer server.Close()

	config := &Config{
		Tools: []ToolConfig{
			{
				Name: "err_tool",
				Handler: ToolHandler{
					Type: "proxy",
					Proxy: &ProxyHandler{
						URL: server.URL,
						ErrorMapping: map[string]string{
							"404": "Not found.",
						},
					},
				},
			},
		},
	}

	registry := NewToolRegistry()
	for _, tool := range config.Tools {
		registry.Register(tool)
	}
	validator, _ := NewSchemaValidator(config.Tools)
	executor := NewToolExecutor(registry, validator, config)

	_, err := executor.Execute(context.Background(), "err_tool", nil)
	if err == nil {
		t.Fatal("Expected error")
	}

	// Should fall through to default HTTP error format
	if err.Message == "Not found." {
		t.Error("Should not have matched 404 mapping for 403 status")
	}
}

// =============================================================================
// P1: Request Context Propagation
// =============================================================================

func TestRequestContextPropagation_InStaticTemplate(t *testing.T) {
	config := &Config{
		Tools: []ToolConfig{
			{
				Name: "ctx_tool",
				Handler: ToolHandler{
					Type:             "static",
					Static:           &StaticHandler{Content: ""},
					ResponseTemplate: "User key: {{ request.key_id }}",
				},
			},
		},
	}

	registry := NewToolRegistry()
	for _, tool := range config.Tools {
		registry.Register(tool)
	}
	validator, _ := NewSchemaValidator(config.Tools)
	executor := NewToolExecutor(registry, validator, config)

	ctx := ContextWithIdentity(context.Background(), []string{"admin"}, "key-abc")
	result, err := executor.Execute(ctx, "ctx_tool", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Content[0].Text != "User key: key-abc" {
		t.Errorf("Expected 'User key: key-abc', got: %s", result.Content[0].Text)
	}
}

// =============================================================================
// P1: Tool Filter (glob matching)
// =============================================================================

func TestMatchesToolFilter_IncludeGlob(t *testing.T) {
	filter := &ToolFilter{Include: []string{"get_*", "list_*"}}

	if !matchesToolFilter("get_users", nil, filter) {
		t.Error("get_users should match include pattern get_*")
	}
	if !matchesToolFilter("list_items", nil, filter) {
		t.Error("list_items should match include pattern list_*")
	}
	if matchesToolFilter("delete_user", nil, filter) {
		t.Error("delete_user should NOT match include patterns")
	}
}

func TestMatchesToolFilter_ExcludeGlob(t *testing.T) {
	filter := &ToolFilter{Exclude: []string{"*_admin_*", "delete_*"}}

	if !matchesToolFilter("get_users", nil, filter) {
		t.Error("get_users should pass (no exclude match)")
	}
	if matchesToolFilter("get_admin_settings", nil, filter) {
		t.Error("get_admin_settings should be excluded")
	}
	if matchesToolFilter("delete_user", nil, filter) {
		t.Error("delete_user should be excluded")
	}
}

func TestMatchesToolFilter_IncludeAndExclude(t *testing.T) {
	filter := &ToolFilter{
		Include: []string{"get_*"},
		Exclude: []string{"get_secret_*"},
	}

	if !matchesToolFilter("get_users", nil, filter) {
		t.Error("get_users should pass")
	}
	if matchesToolFilter("get_secret_key", nil, filter) {
		t.Error("get_secret_key should be excluded")
	}
	if matchesToolFilter("delete_user", nil, filter) {
		t.Error("delete_user should fail include check")
	}
}

func TestMatchesToolFilter_Tags(t *testing.T) {
	filter := &ToolFilter{
		IncludeTags: []string{"read"},
		ExcludeTags: []string{"deprecated"},
	}

	if !matchesToolFilter("tool1", []string{"read", "users"}, filter) {
		t.Error("tool with 'read' tag should pass")
	}
	if matchesToolFilter("tool2", []string{"write"}, filter) {
		t.Error("tool without 'read' tag should fail")
	}
	if matchesToolFilter("tool3", []string{"read", "deprecated"}, filter) {
		t.Error("tool with 'deprecated' tag should be excluded")
	}
}

func TestMatchesToolFilter_Nil(t *testing.T) {
	if !matchesToolFilter("anything", nil, nil) {
		t.Error("nil filter should match everything")
	}
}

func TestFilterTools(t *testing.T) {
	tools := []Tool{
		{Name: "get_user"},
		{Name: "get_admin"},
		{Name: "delete_user"},
	}
	configs := map[string]*ToolConfig{
		"get_user":    {Name: "get_user", Tags: []string{"read"}},
		"get_admin":   {Name: "get_admin", Tags: []string{"read", "admin"}},
		"delete_user": {Name: "delete_user", Tags: []string{"write"}},
	}

	filter := &ToolFilter{
		Include:     []string{"get_*"},
		ExcludeTags: []string{"admin"},
	}

	result := FilterTools(tools, configs, filter)
	if len(result) != 1 {
		t.Fatalf("Expected 1 tool, got %d", len(result))
	}
	if result[0].Name != "get_user" {
		t.Errorf("Expected get_user, got %s", result[0].Name)
	}
}

// =============================================================================
// P1: Federation Tool Filtering
// =============================================================================

func TestFederation_ToolFilter(t *testing.T) {
	mockTools := ListToolsResult{
		Tools: []Tool{
			{Name: "search", InputSchema: json.RawMessage(`{"type":"object"}`)},
			{Name: "admin_reset", InputSchema: json.RawMessage(`{"type":"object"}`)},
			{Name: "get_data", InputSchema: json.RawMessage(`{"type":"object"}`)},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := JSONRPCResponse{JSONRPC: "2.0", ID: 1, Result: &mockTools}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	fed := NewFederation([]FederatedServerConfig{
		{
			URL:    server.URL,
			Prefix: "svc",
			ToolFilter: &ToolFilter{
				Include: []string{"search", "get_*"},
			},
		},
	})

	if err := fed.DiscoverTools(context.Background()); err != nil {
		t.Fatalf("DiscoverTools failed: %v", err)
	}

	tools := fed.ListTools()
	if len(tools) != 2 {
		t.Fatalf("Expected 2 tools (admin_reset filtered), got %d", len(tools))
	}

	// Verify admin_reset was filtered out
	for _, tool := range tools {
		if tool.Name == "svc_admin_reset" {
			t.Error("admin_reset should have been filtered")
		}
	}
}

// =============================================================================
// P1: Federation Tool Overrides
// =============================================================================

func TestFederation_ToolOverrides_Rename(t *testing.T) {
	mockTools := ListToolsResult{
		Tools: []Tool{
			{Name: "search", Description: "Original desc", InputSchema: json.RawMessage(`{"type":"object"}`)},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := JSONRPCResponse{JSONRPC: "2.0", ID: 1, Result: &mockTools}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	fed := NewFederation([]FederatedServerConfig{
		{
			URL:    server.URL,
			Prefix: "svc",
			ToolOverrides: map[string]*ToolOverride{
				"search": {
					Rename:      "find_documents",
					Description: "Find documents in the archive",
				},
			},
		},
	})

	if err := fed.DiscoverTools(context.Background()); err != nil {
		t.Fatalf("DiscoverTools failed: %v", err)
	}

	// Should be renamed (skipping prefix)
	tool, ok := fed.GetTool("find_documents")
	if !ok {
		t.Fatal("Expected to find 'find_documents' (renamed)")
	}
	if tool.Name != "find_documents" {
		t.Errorf("Expected name 'find_documents', got %q", tool.Name)
	}

	// Original prefixed name should not exist
	_, ok = fed.GetTool("svc_search")
	if ok {
		t.Error("svc_search should not exist after rename")
	}
}

func TestFederation_ToolOverrides_Disabled(t *testing.T) {
	mockTools := ListToolsResult{
		Tools: []Tool{
			{Name: "keep_me", InputSchema: json.RawMessage(`{"type":"object"}`)},
			{Name: "remove_me", InputSchema: json.RawMessage(`{"type":"object"}`)},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := JSONRPCResponse{JSONRPC: "2.0", ID: 1, Result: &mockTools}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	fed := NewFederation([]FederatedServerConfig{
		{
			URL: server.URL,
			ToolOverrides: map[string]*ToolOverride{
				"remove_me": {Visibility: VisibilityDisabled},
			},
		},
	})

	if err := fed.DiscoverTools(context.Background()); err != nil {
		t.Fatalf("DiscoverTools failed: %v", err)
	}

	tools := fed.ListTools()
	if len(tools) != 1 {
		t.Fatalf("Expected 1 tool (remove_me disabled), got %d", len(tools))
	}
	if tools[0].Name != "keep_me" {
		t.Errorf("Expected keep_me, got %s", tools[0].Name)
	}
}

// =============================================================================
// P1: OpenAPI Bridge Filtering
// =============================================================================

func TestOpenAPIBridge_ExcludeMethods(t *testing.T) {
	spec := json.RawMessage(`{
		"openapi": "3.0.0",
		"servers": [{"url": "https://api.example.com"}],
		"paths": {
			"/users": {
				"get": {"operationId": "listUsers", "summary": "List users"},
				"post": {"operationId": "createUser", "summary": "Create user"},
				"delete": {"operationId": "deleteUsers", "summary": "Delete all users"}
			}
		}
	}`)

	bridge, err := NewOpenAPIBridge(OpenAPIBridgeConfig{
		SpecInline:     spec,
		ExcludeMethods: []string{"DELETE"},
	}, http.DefaultClient)
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	tools := bridge.Tools()
	if len(tools) != 2 {
		t.Fatalf("Expected 2 tools (DELETE excluded), got %d", len(tools))
	}

	for _, tool := range tools {
		if tool.Method == "DELETE" {
			t.Error("DELETE method should have been excluded")
		}
	}
}

func TestOpenAPIBridge_IncludeOperations(t *testing.T) {
	spec := json.RawMessage(`{
		"openapi": "3.0.0",
		"servers": [{"url": "https://api.example.com"}],
		"paths": {
			"/users": {
				"get": {"operationId": "listUsers", "summary": "List users"},
				"post": {"operationId": "createUser", "summary": "Create user"}
			},
			"/admin": {
				"get": {"operationId": "adminPanel", "summary": "Admin panel"}
			}
		}
	}`)

	bridge, err := NewOpenAPIBridge(OpenAPIBridgeConfig{
		SpecInline:        spec,
		IncludeOperations: []string{"listUsers"},
	}, http.DefaultClient)
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	tools := bridge.Tools()
	if len(tools) != 1 {
		t.Fatalf("Expected 1 tool, got %d", len(tools))
	}
	if tools[0].Name != "listUsers" {
		t.Errorf("Expected listUsers, got %s", tools[0].Name)
	}
}

func TestOpenAPIBridge_ExcludePaths(t *testing.T) {
	spec := json.RawMessage(`{
		"openapi": "3.0.0",
		"servers": [{"url": "https://api.example.com"}],
		"paths": {
			"/users": {
				"get": {"operationId": "listUsers", "summary": "List users"}
			},
			"/admin/settings": {
				"get": {"operationId": "getSettings", "summary": "Get settings"}
			},
			"/admin/users": {
				"get": {"operationId": "adminListUsers", "summary": "Admin list users"}
			}
		}
	}`)

	bridge, err := NewOpenAPIBridge(OpenAPIBridgeConfig{
		SpecInline:   spec,
		ExcludePaths: []string{"/admin/*"},
	}, http.DefaultClient)
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	tools := bridge.Tools()
	if len(tools) != 1 {
		t.Fatalf("Expected 1 tool (/admin/* excluded), got %d", len(tools))
	}
	if tools[0].Name != "listUsers" {
		t.Errorf("Expected listUsers, got %s", tools[0].Name)
	}
}

func TestOpenAPIBridge_OperationOverrides(t *testing.T) {
	spec := json.RawMessage(`{
		"openapi": "3.0.0",
		"servers": [{"url": "https://api.example.com"}],
		"paths": {
			"/users": {
				"get": {"operationId": "listUsers", "summary": "Original desc"}
			}
		}
	}`)

	bridge, err := NewOpenAPIBridge(OpenAPIBridgeConfig{
		SpecInline: spec,
		OperationOverrides: map[string]*OperationOverride{
			"listUsers": {
				Name:        "find_users",
				Description: "Custom description",
			},
		},
	}, http.DefaultClient)
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	tools := bridge.Tools()
	if len(tools) != 1 {
		t.Fatalf("Expected 1 tool, got %d", len(tools))
	}
	if tools[0].Name != "find_users" {
		t.Errorf("Expected name 'find_users', got %s", tools[0].Name)
	}
	if tools[0].Description != "Custom description" {
		t.Errorf("Expected custom description, got %s", tools[0].Description)
	}
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkMatchesToolFilter(b *testing.B) {
	b.ReportAllocs()

	filter := &ToolFilter{
		Include: []string{"get_*", "list_*", "search_*"},
		Exclude: []string{"*_internal"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matchesToolFilter("get_users", nil, filter)
	}
}

func BenchmarkFilterTools(b *testing.B) {
	b.ReportAllocs()

	tools := make([]Tool, 50)
	configs := make(map[string]*ToolConfig, 50)
	for i := 0; i < 50; i++ {
		name := "tool_" + string(rune('a'+i%26))
		tools[i] = Tool{Name: name}
		configs[name] = &ToolConfig{Name: name, Tags: []string{"read"}}
	}

	filter := &ToolFilter{Include: []string{"tool_*"}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FilterTools(tools, configs, filter)
	}
}
