package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// =============================================================================
// P0-1: AccessChecker wired into Handler
// =============================================================================

func TestHandler_AccessChecker_ToolsList_Filtered(t *testing.T) {
	config := &Config{
		ServerInfo:   ServerInfo{Name: "test", Version: "1.0"},
		Capabilities: Capabilities{Tools: &ToolsCapability{}},
		Tools: []ToolConfig{
			{
				Name:        "public_tool",
				Description: "Anyone can use",
				InputSchema: json.RawMessage(`{"type":"object"}`),
				Handler:     ToolHandler{Type: "static", Static: &StaticHandler{Content: `{}`}},
			},
			{
				Name:        "admin_tool",
				Description: "Admin only",
				InputSchema: json.RawMessage(`{"type":"object"}`),
				Handler:     ToolHandler{Type: "static", Static: &StaticHandler{Content: `{}`}},
				Access:      &ToolAccessConfig{AllowedRoles: []string{"admin"}},
			},
		},
	}

	handler, err := NewHandler(config)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	// Request without identity - should only see public_tool
	reqBody := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var resp JSONRPCResponse
	json.NewDecoder(w.Result().Body).Decode(&resp)

	resultMap := resp.Result.(map[string]interface{})
	tools := resultMap["tools"].([]interface{})

	if len(tools) != 1 {
		t.Fatalf("Expected 1 tool (public only), got %d", len(tools))
	}

	toolName := tools[0].(map[string]interface{})["name"].(string)
	if toolName != "public_tool" {
		t.Errorf("Expected public_tool, got %s", toolName)
	}

	// Request with admin role - should see both
	req2 := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	ctx := ContextWithIdentity(req2.Context(), []string{"admin"}, "")
	req2 = req2.WithContext(ctx)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	var resp2 JSONRPCResponse
	json.NewDecoder(w2.Result().Body).Decode(&resp2)

	resultMap2 := resp2.Result.(map[string]interface{})
	tools2 := resultMap2["tools"].([]interface{})

	if len(tools2) != 2 {
		t.Errorf("Expected 2 tools for admin, got %d", len(tools2))
	}
}

func TestHandler_AccessChecker_ToolsCall_Denied(t *testing.T) {
	config := &Config{
		ServerInfo:   ServerInfo{Name: "test", Version: "1.0"},
		Capabilities: Capabilities{Tools: &ToolsCapability{}},
		Tools: []ToolConfig{
			{
				Name:        "admin_tool",
				InputSchema: json.RawMessage(`{"type":"object"}`),
				Handler:     ToolHandler{Type: "static", Static: &StaticHandler{Content: `{"ok":true}`}},
				Access:      &ToolAccessConfig{AllowedRoles: []string{"admin"}},
			},
		},
	}

	handler, err := NewHandler(config)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	// Call without identity - should get "tool not found" (not "access denied")
	reqBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"admin_tool","arguments":{}}}`
	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var resp JSONRPCResponse
	body, _ := io.ReadAll(w.Result().Body)
	json.Unmarshal(body, &resp)

	if resp.Error == nil {
		t.Fatal("Expected error for unauthorized access")
	}
	if resp.Error.Code != CodeToolNotFound {
		t.Errorf("Expected tool not found error (no info leakage), got code %d", resp.Error.Code)
	}
}

func TestHandler_AccessChecker_ToolsCall_AllowedWithRole(t *testing.T) {
	config := &Config{
		ServerInfo:   ServerInfo{Name: "test", Version: "1.0"},
		Capabilities: Capabilities{Tools: &ToolsCapability{}},
		Tools: []ToolConfig{
			{
				Name:        "admin_tool",
				InputSchema: json.RawMessage(`{"type":"object"}`),
				Handler:     ToolHandler{Type: "static", Static: &StaticHandler{Content: `{"ok":true}`}},
				Access:      &ToolAccessConfig{AllowedRoles: []string{"admin"}},
			},
		},
	}

	handler, err := NewHandler(config)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"admin_tool","arguments":{}}}`
	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	ctx := ContextWithIdentity(req.Context(), []string{"admin"}, "")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var resp JSONRPCResponse
	body, _ := io.ReadAll(w.Result().Body)
	json.Unmarshal(body, &resp)

	if resp.Error != nil {
		t.Errorf("Expected no error for admin, got: %v", resp.Error)
	}
}

// =============================================================================
// P0-2: Tool Visibility
// =============================================================================

func TestToolRegistry_Visibility_Disabled(t *testing.T) {
	registry := NewToolRegistry()

	err := registry.Register(ToolConfig{
		Name:       "disabled_tool",
		Visibility: VisibilityDisabled,
	})
	if err != nil {
		t.Fatalf("Register disabled tool should not error: %v", err)
	}

	// Disabled tool should not be findable
	if registry.Has("disabled_tool") {
		t.Error("Disabled tool should not be in registry")
	}

	_, getErr := registry.Get("disabled_tool")
	if getErr == nil {
		t.Error("Get on disabled tool should return error")
	}

	tools := registry.List()
	if len(tools) != 0 {
		t.Errorf("Expected 0 tools in list, got %d", len(tools))
	}
}

func TestToolRegistry_Visibility_Hidden(t *testing.T) {
	registry := NewToolRegistry()

	registry.Register(ToolConfig{
		Name:        "hidden_tool",
		Description: "Secret tool",
		Visibility:  VisibilityHidden,
		Handler:     ToolHandler{Type: "static", Static: &StaticHandler{Content: `{}`}},
	})
	registry.Register(ToolConfig{
		Name:        "visible_tool",
		Description: "Public tool",
	})

	// Hidden tool should be callable
	if !registry.Has("hidden_tool") {
		t.Error("Hidden tool should be in registry (callable)")
	}

	tool, err := registry.Get("hidden_tool")
	if err != nil {
		t.Fatalf("Get hidden tool should work: %v", err)
	}
	if tool.Name != "hidden_tool" {
		t.Errorf("Expected hidden_tool, got %s", tool.Name)
	}

	// But not listed
	tools := registry.List()
	if len(tools) != 1 {
		t.Fatalf("Expected 1 tool in list (hidden excluded), got %d", len(tools))
	}
	if tools[0].Name != "visible_tool" {
		t.Errorf("Expected visible_tool in list, got %s", tools[0].Name)
	}
}

func TestToolRegistry_Visibility_Default(t *testing.T) {
	registry := NewToolRegistry()

	// No visibility set = enabled by default
	registry.Register(ToolConfig{Name: "default_tool"})

	if !registry.Has("default_tool") {
		t.Error("Default visibility tool should be registered")
	}

	tools := registry.List()
	if len(tools) != 1 {
		t.Errorf("Expected 1 tool, got %d", len(tools))
	}
}

func TestHandler_HiddenTool_Callable(t *testing.T) {
	config := &Config{
		ServerInfo:   ServerInfo{Name: "test", Version: "1.0"},
		Capabilities: Capabilities{Tools: &ToolsCapability{}},
		Tools: []ToolConfig{
			{
				Name:        "hidden_tool",
				Visibility:  VisibilityHidden,
				InputSchema: json.RawMessage(`{"type":"object"}`),
				Handler:     ToolHandler{Type: "static", Static: &StaticHandler{Content: `{"secret":true}`}},
			},
		},
	}

	handler, err := NewHandler(config)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	// tools/list should return empty
	listBody := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	listReq := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(listBody))
	listW := httptest.NewRecorder()
	handler.ServeHTTP(listW, listReq)

	var listResp JSONRPCResponse
	json.NewDecoder(listW.Result().Body).Decode(&listResp)
	tools := listResp.Result.(map[string]interface{})["tools"].([]interface{})
	if len(tools) != 0 {
		t.Errorf("Expected 0 tools in list (hidden), got %d", len(tools))
	}

	// tools/call should still work
	callBody := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"hidden_tool","arguments":{}}}`
	callReq := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(callBody))
	callW := httptest.NewRecorder()
	handler.ServeHTTP(callW, callReq)

	var callResp JSONRPCResponse
	json.NewDecoder(callW.Result().Body).Decode(&callResp)
	if callResp.Error != nil {
		t.Errorf("Expected hidden tool to be callable, got error: %v", callResp.Error)
	}
}

// =============================================================================
// P0-3: Tool Annotations
// =============================================================================

func TestToolAnnotations_InToolsList(t *testing.T) {
	readOnly := true
	destructive := false

	config := &Config{
		ServerInfo:   ServerInfo{Name: "test", Version: "1.0"},
		Capabilities: Capabilities{Tools: &ToolsCapability{}},
		Tools: []ToolConfig{
			{
				Name:        "read_tool",
				InputSchema: json.RawMessage(`{"type":"object"}`),
				Handler:     ToolHandler{Type: "static", Static: &StaticHandler{Content: `{}`}},
				Annotations: &ToolAnnotations{
					ReadOnlyHint:    &readOnly,
					DestructiveHint: &destructive,
				},
			},
		},
	}

	handler, err := NewHandler(config)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)

	var resp JSONRPCResponse
	json.Unmarshal(body, &resp)

	resultMap := resp.Result.(map[string]interface{})
	tools := resultMap["tools"].([]interface{})
	if len(tools) != 1 {
		t.Fatalf("Expected 1 tool, got %d", len(tools))
	}

	tool := tools[0].(map[string]interface{})
	annotations, ok := tool["annotations"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected annotations in tool response")
	}

	if annotations["readOnlyHint"] != true {
		t.Errorf("Expected readOnlyHint=true, got %v", annotations["readOnlyHint"])
	}
	if annotations["destructiveHint"] != false {
		t.Errorf("Expected destructiveHint=false, got %v", annotations["destructiveHint"])
	}
}

func TestToolAnnotations_NilWhenNotSet(t *testing.T) {
	config := &Config{
		ServerInfo:   ServerInfo{Name: "test", Version: "1.0"},
		Capabilities: Capabilities{Tools: &ToolsCapability{}},
		Tools: []ToolConfig{
			{
				Name:        "plain_tool",
				InputSchema: json.RawMessage(`{"type":"object"}`),
				Handler:     ToolHandler{Type: "static", Static: &StaticHandler{Content: `{}`}},
			},
		},
	}

	handler, err := NewHandler(config)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)

	var resp JSONRPCResponse
	json.Unmarshal(body, &resp)

	resultMap := resp.Result.(map[string]interface{})
	tools := resultMap["tools"].([]interface{})
	tool := tools[0].(map[string]interface{})

	if _, ok := tool["annotations"]; ok {
		t.Error("Expected no annotations when not configured")
	}
}

// =============================================================================
// P0-5: Response Mapping
// =============================================================================

func TestResponseMapping_FlatExtraction(t *testing.T) {
	data := map[string]interface{}{
		"data": map[string]interface{}{
			"user": map[string]interface{}{
				"full_name": "Alice Smith",
				"email":     "alice@example.com",
				"team": map[string]interface{}{
					"name": "Engineering",
				},
			},
		},
	}

	mapping := map[string]string{
		"name":  "data.user.full_name",
		"email": "data.user.email",
		"team":  "data.user.team.name",
	}

	result := applyResponseMapping(data, mapping)
	mapped := result.(map[string]interface{})

	if mapped["name"] != "Alice Smith" {
		t.Errorf("Expected 'Alice Smith', got %v", mapped["name"])
	}
	if mapped["email"] != "alice@example.com" {
		t.Errorf("Expected 'alice@example.com', got %v", mapped["email"])
	}
	if mapped["team"] != "Engineering" {
		t.Errorf("Expected 'Engineering', got %v", mapped["team"])
	}
}

func TestResponseMapping_ArrayIndex(t *testing.T) {
	data := map[string]interface{}{
		"items": []interface{}{
			map[string]interface{}{"id": "first"},
			map[string]interface{}{"id": "second"},
		},
	}

	mapping := map[string]string{
		"first_id":  "items.0.id",
		"second_id": "items.1.id",
	}

	result := applyResponseMapping(data, mapping)
	mapped := result.(map[string]interface{})

	if mapped["first_id"] != "first" {
		t.Errorf("Expected 'first', got %v", mapped["first_id"])
	}
	if mapped["second_id"] != "second" {
		t.Errorf("Expected 'second', got %v", mapped["second_id"])
	}
}

func TestResponseMapping_MissingPath(t *testing.T) {
	data := map[string]interface{}{"a": "b"}

	mapping := map[string]string{
		"missing": "x.y.z",
	}

	result := applyResponseMapping(data, mapping)
	mapped := result.(map[string]interface{})

	if mapped["missing"] != nil {
		t.Errorf("Expected nil for missing path, got %v", mapped["missing"])
	}
}

func TestResponseMapping_WithProxyHandler(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"user": map[string]interface{}{
					"name":  "Bob",
					"email": "bob@test.com",
					"age":   float64(30),
				},
			},
		})
	}))
	defer server.Close()

	config := &Config{
		Tools: []ToolConfig{
			{
				Name: "mapped_tool",
				Handler: ToolHandler{
					Type: "proxy",
					Proxy: &ProxyHandler{
						URL: server.URL,
						ResponseMapping: map[string]string{
							"name":  "data.user.name",
							"email": "data.user.email",
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

	result, execErr := executor.Execute(context.Background(), "mapped_tool", nil)
	if execErr != nil {
		t.Fatalf("Unexpected error: %v", execErr)
	}

	var content map[string]interface{}
	json.Unmarshal([]byte(result.Content[0].Text), &content)

	if content["name"] != "Bob" {
		t.Errorf("Expected 'Bob', got %v", content["name"])
	}
	if content["email"] != "bob@test.com" {
		t.Errorf("Expected 'bob@test.com', got %v", content["email"])
	}
	// Should NOT have the full nested structure
	if _, ok := content["data"]; ok {
		t.Error("Expected mapping to exclude unmapped fields")
	}
}

// =============================================================================
// P0-6: Body Template
// =============================================================================

func TestBodyTemplate_StructuredJSON(t *testing.T) {
	var receivedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedBody)

		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"created":true}`))
	}))
	defer server.Close()

	config := &Config{
		Tools: []ToolConfig{
			{
				Name: "create_issue",
				Handler: ToolHandler{
					Type: "proxy",
					Proxy: &ProxyHandler{
						URL:    server.URL,
						Method: "POST",
						BodyTemplate: map[string]interface{}{
							"fields": map[string]interface{}{
								"project": map[string]interface{}{"key": "SUP"},
								"summary": "{{ tool.arguments.title }}",
							},
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

	args := map[string]interface{}{"title": "Fix the bug"}
	_, execErr := executor.Execute(context.Background(), "create_issue", args)
	if execErr != nil {
		t.Fatalf("Unexpected error: %v", execErr)
	}

	fields := receivedBody["fields"].(map[string]interface{})
	project := fields["project"].(map[string]interface{})
	if project["key"] != "SUP" {
		t.Errorf("Expected project key 'SUP', got %v", project["key"])
	}
	if fields["summary"] != "Fix the bug" {
		t.Errorf("Expected summary 'Fix the bug', got %v", fields["summary"])
	}
}

func TestBodyTemplate_PrecedenceOverBody(t *testing.T) {
	var receivedBody string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	config := &Config{
		Tools: []ToolConfig{
			{
				Name: "both_body",
				Handler: ToolHandler{
					Type: "proxy",
					Proxy: &ProxyHandler{
						URL:    server.URL,
						Method: "POST",
						Body:   `{"from":"body_field"}`,
						BodyTemplate: map[string]interface{}{
							"from": "body_template",
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

	_, execErr := executor.Execute(context.Background(), "both_body", nil)
	if execErr != nil {
		t.Fatalf("Unexpected error: %v", execErr)
	}

	var parsed map[string]interface{}
	json.Unmarshal([]byte(receivedBody), &parsed)
	if parsed["from"] != "body_template" {
		t.Errorf("Expected body_template to take precedence, got body: %s", receivedBody)
	}
}

// =============================================================================
// P0-7: Query Params
// =============================================================================

func TestQueryParams_URLEncoding(t *testing.T) {
	var receivedURL string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedURL = r.URL.String()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	config := &Config{
		Tools: []ToolConfig{
			{
				Name: "search",
				Handler: ToolHandler{
					Type: "proxy",
					Proxy: &ProxyHandler{
						URL: server.URL + "/api/search",
						QueryParams: map[string]string{
							"q":     "{{ tool.arguments.query }}",
							"limit": "{{ tool.arguments.limit }}",
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

	args := map[string]interface{}{"query": "hello world", "limit": "10"}
	_, execErr := executor.Execute(context.Background(), "search", args)
	if execErr != nil {
		t.Fatalf("Unexpected error: %v", execErr)
	}

	// URL should be properly encoded
	if receivedURL != "/api/search?limit=10&q=hello+world" {
		t.Errorf("Expected properly encoded URL, got %s", receivedURL)
	}
}

func TestQueryParams_EmptyValueSkipped(t *testing.T) {
	var receivedURL string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedURL = r.URL.String()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	config := &Config{
		Tools: []ToolConfig{
			{
				Name: "search",
				Handler: ToolHandler{
					Type: "proxy",
					Proxy: &ProxyHandler{
						URL: server.URL + "/api/search",
						QueryParams: map[string]string{
							"q":      "{{ tool.arguments.query }}",
							"filter": "{{ tool.arguments.filter }}",
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

	// Only provide query, not filter
	args := map[string]interface{}{"query": "test"}
	_, execErr := executor.Execute(context.Background(), "search", args)
	if execErr != nil {
		t.Fatalf("Unexpected error: %v", execErr)
	}

	if receivedURL != "/api/search?q=test" {
		t.Errorf("Expected empty param to be skipped, got URL: %s", receivedURL)
	}
}

func TestQueryParams_WithExistingURLParams(t *testing.T) {
	var receivedURL string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedURL = r.URL.String()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	config := &Config{
		Tools: []ToolConfig{
			{
				Name: "search",
				Handler: ToolHandler{
					Type: "proxy",
					Proxy: &ProxyHandler{
						URL: server.URL + "/api/search?version=2",
						QueryParams: map[string]string{
							"q": "{{ tool.arguments.query }}",
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

	args := map[string]interface{}{"query": "test"}
	_, execErr := executor.Execute(context.Background(), "search", args)
	if execErr != nil {
		t.Fatalf("Unexpected error: %v", execErr)
	}

	// Should merge with existing params
	if receivedURL != "/api/search?q=test&version=2" {
		t.Errorf("Expected merged params, got URL: %s", receivedURL)
	}
}

// =============================================================================
// P0: ContextWithIdentity
// =============================================================================

func TestContextWithIdentity(t *testing.T) {
	ctx := context.Background()
	ctx = ContextWithIdentity(ctx, []string{"admin", "user"}, "key-123")

	roles, keyID := extractIdentity(ctx)
	if len(roles) != 2 || roles[0] != "admin" || roles[1] != "user" {
		t.Errorf("Expected [admin, user] roles, got %v", roles)
	}
	if keyID != "key-123" {
		t.Errorf("Expected key-123, got %s", keyID)
	}
}

func TestContextWithIdentity_Empty(t *testing.T) {
	ctx := context.Background()

	roles, keyID := extractIdentity(ctx)
	if len(roles) != 0 {
		t.Errorf("Expected no roles, got %v", roles)
	}
	if keyID != "" {
		t.Errorf("Expected empty keyID, got %s", keyID)
	}
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkResponseMapping(b *testing.B) {
	b.ReportAllocs()

	data := map[string]interface{}{
		"data": map[string]interface{}{
			"user": map[string]interface{}{
				"full_name": "Alice Smith",
				"email":     "alice@example.com",
				"team": map[string]interface{}{
					"name": "Engineering",
				},
			},
		},
	}

	mapping := map[string]string{
		"name":  "data.user.full_name",
		"email": "data.user.email",
		"team":  "data.user.team.name",
	}

	for i := 0; i < b.N; i++ {
		applyResponseMapping(data, mapping)
	}
}

func BenchmarkExtractByPath(b *testing.B) {
	b.ReportAllocs()

	data := map[string]interface{}{
		"deeply": map[string]interface{}{
			"nested": map[string]interface{}{
				"value": "found",
			},
		},
	}

	for i := 0; i < b.N; i++ {
		extractByPath(data, "deeply.nested.value")
	}
}

func BenchmarkToolRegistryList(b *testing.B) {
	b.ReportAllocs()

	registry := NewToolRegistry()
	for i := 0; i < 50; i++ {
		registry.Register(ToolConfig{
			Name:        "tool_" + strconv.Itoa(i),
			Description: "A test tool",
			InputSchema: json.RawMessage(`{"type":"object"}`),
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		registry.List()
	}
}

func BenchmarkAccessCheckerCheck(b *testing.B) {
	b.ReportAllocs()

	rules := map[string]*ToolAccessConfig{
		"admin_tool": {AllowedRoles: []string{"admin", "superadmin"}},
		"user_tool":  {AllowedRoles: []string{"user", "admin"}},
	}
	checker := NewAccessChecker(rules)
	roles := []string{"user"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checker.Check("user_tool", roles, "")
	}
}

func BenchmarkHandlerToolsList(b *testing.B) {
	b.ReportAllocs()

	config := &Config{
		ServerInfo:   ServerInfo{Name: "bench", Version: "1.0"},
		Capabilities: Capabilities{Tools: &ToolsCapability{}},
		Tools: []ToolConfig{
			{Name: "tool1", InputSchema: json.RawMessage(`{"type":"object"}`), Handler: ToolHandler{Type: "static", Static: &StaticHandler{Content: `{}`}}},
			{Name: "tool2", InputSchema: json.RawMessage(`{"type":"object"}`), Handler: ToolHandler{Type: "static", Static: &StaticHandler{Content: `{}`}}},
			{Name: "tool3", InputSchema: json.RawMessage(`{"type":"object"}`), Handler: ToolHandler{Type: "static", Static: &StaticHandler{Content: `{}`}}},
		},
	}

	handler, _ := NewHandler(config)
	reqBody := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/mcp", bytes.NewReader(reqBody))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}
