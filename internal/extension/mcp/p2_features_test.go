package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// =============================================================================
// P1: Per-Tool Auth
// =============================================================================

func TestToolAuth_BearerToken(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	config := &Config{
		Tools: []ToolConfig{{
			Name: "auth_tool",
			Handler: ToolHandler{
				Type: "proxy",
				Proxy: &ProxyHandler{
					URL:  server.URL,
					Auth: &ToolAuthConfig{Type: "bearer_token", Token: "my-secret-token"},
				},
			},
		}},
	}

	registry := NewToolRegistry()
	for _, tool := range config.Tools {
		registry.Register(tool)
	}
	validator, _ := NewSchemaValidator(config.Tools)
	executor := NewToolExecutor(registry, validator, config)

	_, err := executor.Execute(context.Background(), "auth_tool", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if receivedAuth != "Bearer my-secret-token" {
		t.Errorf("Expected 'Bearer my-secret-token', got %q", receivedAuth)
	}
}

func TestToolAuth_APIKey_Header(t *testing.T) {
	var receivedKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKey = r.Header.Get("X-Custom-Key")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	config := &Config{
		Tools: []ToolConfig{{
			Name: "apikey_tool",
			Handler: ToolHandler{
				Type: "proxy",
				Proxy: &ProxyHandler{
					URL: server.URL,
					Auth: &ToolAuthConfig{
						Type:       "api_key",
						APIKey:     "key-123",
						APIKeyName: "X-Custom-Key",
					},
				},
			},
		}},
	}

	registry := NewToolRegistry()
	for _, tool := range config.Tools {
		registry.Register(tool)
	}
	validator, _ := NewSchemaValidator(config.Tools)
	executor := NewToolExecutor(registry, validator, config)

	_, err := executor.Execute(context.Background(), "apikey_tool", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if receivedKey != "key-123" {
		t.Errorf("Expected 'key-123', got %q", receivedKey)
	}
}

func TestToolAuth_APIKey_Query(t *testing.T) {
	var receivedKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKey = r.URL.Query().Get("api_key")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	config := &Config{
		Tools: []ToolConfig{{
			Name: "query_key_tool",
			Handler: ToolHandler{
				Type: "proxy",
				Proxy: &ProxyHandler{
					URL: server.URL,
					Auth: &ToolAuthConfig{
						Type:       "api_key",
						APIKey:     "qkey-456",
						APIKeyName: "api_key",
						APIKeyIn:   "query",
					},
				},
			},
		}},
	}

	registry := NewToolRegistry()
	for _, tool := range config.Tools {
		registry.Register(tool)
	}
	validator, _ := NewSchemaValidator(config.Tools)
	executor := NewToolExecutor(registry, validator, config)

	_, err := executor.Execute(context.Background(), "query_key_tool", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if receivedKey != "qkey-456" {
		t.Errorf("Expected 'qkey-456', got %q", receivedKey)
	}
}

func TestToolAuth_Basic(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	config := &Config{
		Tools: []ToolConfig{{
			Name: "basic_tool",
			Handler: ToolHandler{
				Type: "proxy",
				Proxy: &ProxyHandler{
					URL: server.URL,
					Auth: &ToolAuthConfig{
						Type:     "basic",
						Username: "admin",
						Password: "secret",
					},
				},
			},
		}},
	}

	registry := NewToolRegistry()
	for _, tool := range config.Tools {
		registry.Register(tool)
	}
	validator, _ := NewSchemaValidator(config.Tools)
	executor := NewToolExecutor(registry, validator, config)

	_, err := executor.Execute(context.Background(), "basic_tool", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret"))
	if receivedAuth != expected {
		t.Errorf("Expected %q, got %q", expected, receivedAuth)
	}
}

// =============================================================================
// P2: Pagination
// =============================================================================

func TestPagination_Cursor(t *testing.T) {
	page := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cursor := r.URL.Query().Get("cursor")
		w.Header().Set("Content-Type", "application/json")

		switch {
		case page == 0 && cursor == "":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data":        []interface{}{"a", "b"},
				"next_cursor": "page2",
			})
		case cursor == "page2":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data":        []interface{}{"c", "d"},
				"next_cursor": "",
			})
		}
		page++
	}))
	defer server.Close()

	config := &Config{
		Tools: []ToolConfig{{
			Name: "paginated",
			Handler: ToolHandler{
				Type: "proxy",
				Proxy: &ProxyHandler{
					URL: server.URL,
					Pagination: &PaginationConfig{
						Type:           "cursor",
						NextCursorPath: "next_cursor",
						ResultsPath:    "data",
						CursorParam:    "cursor",
						MaxPages:       5,
					},
				},
			},
		}},
	}

	registry := NewToolRegistry()
	for _, tool := range config.Tools {
		registry.Register(tool)
	}
	validator, _ := NewSchemaValidator(config.Tools)
	executor := NewToolExecutor(registry, validator, config)

	result, err := executor.Execute(context.Background(), "paginated", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should have aggregated results from both pages
	var items []interface{}
	json.Unmarshal([]byte(result.Content[0].Text), &items)

	if len(items) != 4 {
		t.Errorf("Expected 4 aggregated items, got %d: %s", len(items), result.Content[0].Text)
	}
}

func TestPagination_LinkHeader(t *testing.T) {
	page1URL := ""
	page2URL := ""

	mux := http.NewServeMux()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r)
	}))
	defer server.Close()

	page1URL = server.URL + "/page1"
	page2URL = server.URL + "/page2"

	mux.HandleFunc("/page1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", fmt.Sprintf(`<%s>; rel="next"`, page2URL))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]interface{}{"x"})
	})
	mux.HandleFunc("/page2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]interface{}{"y"})
	})

	config := &Config{
		Tools: []ToolConfig{{
			Name: "link_paginated",
			Handler: ToolHandler{
				Type: "proxy",
				Proxy: &ProxyHandler{
					URL: page1URL,
					Pagination: &PaginationConfig{
						Type:     "link_header",
						MaxPages: 5,
					},
				},
			},
		}},
	}

	registry := NewToolRegistry()
	for _, tool := range config.Tools {
		registry.Register(tool)
	}
	validator, _ := NewSchemaValidator(config.Tools)
	executor := NewToolExecutor(registry, validator, config)

	result, err := executor.Execute(context.Background(), "link_paginated", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	var items []interface{}
	json.Unmarshal([]byte(result.Content[0].Text), &items)

	if len(items) != 2 {
		t.Errorf("Expected 2 items, got %d", len(items))
	}
}

func TestParseLinkHeader(t *testing.T) {
	tests := []struct {
		header   string
		rel      string
		expected string
	}{
		{`<https://api.example.com/items?page=2>; rel="next"`, "next", "https://api.example.com/items?page=2"},
		{`<https://api.example.com/items?page=1>; rel="prev", <https://api.example.com/items?page=3>; rel="next"`, "next", "https://api.example.com/items?page=3"},
		{`<https://api.example.com/items?page=1>; rel="prev"`, "next", ""},
		{"", "next", ""},
	}

	for _, tt := range tests {
		got := parseLinkHeader(tt.header, tt.rel)
		if got != tt.expected {
			t.Errorf("parseLinkHeader(%q, %q) = %q, want %q", tt.header, tt.rel, got, tt.expected)
		}
	}
}

// =============================================================================
// P2: Content Type (image/resource)
// =============================================================================

func TestContentType_Image(t *testing.T) {
	imageData := []byte{0x89, 0x50, 0x4E, 0x47} // PNG header bytes

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(imageData)
	}))
	defer server.Close()

	config := &Config{
		Tools: []ToolConfig{{
			Name: "image_tool",
			Handler: ToolHandler{
				Type: "proxy",
				Proxy: &ProxyHandler{
					URL:             server.URL,
					ContentType:     "image",
					ContentMimeType: "image/png",
				},
			},
		}},
	}

	registry := NewToolRegistry()
	for _, tool := range config.Tools {
		registry.Register(tool)
	}
	validator, _ := NewSchemaValidator(config.Tools)
	executor := NewToolExecutor(registry, validator, config)

	result, err := executor.Execute(context.Background(), "image_tool", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Content[0].Type != "image" {
		t.Errorf("Expected content type 'image', got %s", result.Content[0].Type)
	}
	if result.Content[0].MimeType != "image/png" {
		t.Errorf("Expected mimeType 'image/png', got %s", result.Content[0].MimeType)
	}

	decoded, _ := base64.StdEncoding.DecodeString(result.Content[0].Data)
	if !bytes.Equal(decoded, imageData) {
		t.Error("Decoded image data doesn't match")
	}
}

func TestContentType_Auto_DetectsImage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/jpeg")
		w.Write([]byte{0xFF, 0xD8})
	}))
	defer server.Close()

	config := &Config{
		Tools: []ToolConfig{{
			Name: "auto_tool",
			Handler: ToolHandler{
				Type: "proxy",
				Proxy: &ProxyHandler{
					URL:         server.URL,
					ContentType: "auto",
				},
			},
		}},
	}

	registry := NewToolRegistry()
	for _, tool := range config.Tools {
		registry.Register(tool)
	}
	validator, _ := NewSchemaValidator(config.Tools)
	executor := NewToolExecutor(registry, validator, config)

	result, err := executor.Execute(context.Background(), "auto_tool", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Content[0].Type != "image" {
		t.Errorf("Expected auto-detected 'image', got %s", result.Content[0].Type)
	}
}

// =============================================================================
// P2: OpenAPI Bridge $ref Resolution
// =============================================================================

func TestResolveRefs_SimpleRef(t *testing.T) {
	spec := map[string]any{
		"components": map[string]any{
			"schemas": map[string]any{
				"User": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"name":  map[string]any{"type": "string"},
						"email": map[string]any{"type": "string"},
					},
				},
			},
		},
		"paths": map[string]any{
			"/users": map[string]any{
				"post": map[string]any{
					"requestBody": map[string]any{
						"content": map[string]any{
							"application/json": map[string]any{
								"schema": map[string]any{
									"$ref": "#/components/schemas/User",
								},
							},
						},
					},
				},
			},
		},
	}

	ResolveRefs(spec)

	// The $ref should be replaced with the actual schema
	paths := spec["paths"].(map[string]any)
	post := paths["/users"].(map[string]any)["post"].(map[string]any)
	body := post["requestBody"].(map[string]any)
	content := body["content"].(map[string]any)
	jsonContent := content["application/json"].(map[string]any)
	schema := jsonContent["schema"].(map[string]any)

	// Should have the resolved properties, not $ref
	if _, hasRef := schema["$ref"]; hasRef {
		t.Error("$ref should have been resolved")
	}

	props := schema["properties"].(map[string]any)
	if _, ok := props["name"]; !ok {
		t.Error("Expected 'name' property from resolved User schema")
	}
	if _, ok := props["email"]; !ok {
		t.Error("Expected 'email' property from resolved User schema")
	}
}

func TestResolveRefs_NoComponents(t *testing.T) {
	spec := map[string]any{
		"paths": map[string]any{},
	}
	// Should not panic
	ResolveRefs(spec)
}

func TestOpenAPIBridge_WithRefResolution(t *testing.T) {
	spec := json.RawMessage(`{
		"openapi": "3.0.0",
		"servers": [{"url": "https://api.example.com"}],
		"components": {
			"schemas": {
				"CreateUserBody": {
					"type": "object",
					"properties": {
						"name": {"type": "string"},
						"email": {"type": "string"}
					},
					"required": ["name"]
				}
			}
		},
		"paths": {
			"/users": {
				"post": {
					"operationId": "createUser",
					"summary": "Create a user",
					"requestBody": {
						"content": {
							"application/json": {
								"schema": {"$ref": "#/components/schemas/CreateUserBody"}
							}
						}
					}
				}
			}
		}
	}`)

	bridge, err := NewOpenAPIBridge(OpenAPIBridgeConfig{SpecInline: spec}, http.DefaultClient)
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	tools := bridge.Tools()
	if len(tools) != 1 {
		t.Fatalf("Expected 1 tool, got %d", len(tools))
	}

	// The tool should have the resolved properties in its input schema
	var schema map[string]any
	json.Unmarshal(tools[0].InputSchema, &schema)

	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatal("Expected properties in schema")
	}
	if _, ok := props["name"]; !ok {
		t.Error("Expected 'name' property from resolved $ref")
	}
}

// =============================================================================
// P2: Audit Logging
// =============================================================================

func TestAuditLogger_LogToolCall(t *testing.T) {
	logger := NewAuditLogger(nil)

	// Should not panic
	logger.LogToolCall(AuditEntry{
		ToolName: "test_tool",
		Roles:    []string{"admin"},
		KeyID:    "key-123",
		IsError:  false,
		Latency:  42000000, // 42ms
		Cached:   false,
	})
}

// =============================================================================
// P2: Completion
// =============================================================================

func TestHandler_Completion_ResourceURI(t *testing.T) {
	config := &Config{
		ServerInfo:   ServerInfo{Name: "test", Version: "1.0"},
		Capabilities: Capabilities{},
		Resources: []ResourceConfig{
			{URI: "data://users", Name: "Users"},
			{URI: "data://orders", Name: "Orders"},
			{URI: "config://settings", Name: "Settings"},
		},
	}

	handler, err := NewHandler(config)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{"ref":{"type":"ref/resource"},"argument":{"name":"uri","value":"data://"}}}`
	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)
	var resp JSONRPCResponse
	json.Unmarshal(body, &resp)

	if resp.Error != nil {
		t.Fatalf("Expected no error, got: %v", resp.Error)
	}

	resultMap := resp.Result.(map[string]interface{})
	completion := resultMap["completion"].(map[string]interface{})
	values := completion["values"].([]interface{})

	if len(values) != 2 {
		t.Errorf("Expected 2 completions (data://users, data://orders), got %d", len(values))
	}
}

func TestHandler_Completion_PromptArgument(t *testing.T) {
	config := &Config{
		ServerInfo:   ServerInfo{Name: "test", Version: "1.0"},
		Capabilities: Capabilities{Prompts: &PromptsCapability{}},
		Prompts: []PromptConfig{
			{
				Name:      "greet",
				Arguments: []PromptArgument{{Name: "name", Required: true}},
				Messages:  []PromptMessage{{Role: "user", Content: "Hi {{ arguments.name }}"}},
			},
		},
	}

	handler, err := NewHandler(config)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"greet"},"argument":{"name":"name","value":"A"}}}`
	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var resp JSONRPCResponse
	json.NewDecoder(w.Result().Body).Decode(&resp)

	if resp.Error != nil {
		t.Fatalf("Expected no error, got: %v", resp.Error)
	}
}

// =============================================================================
// P2: ExecuteTool (in-process forwarding)
// =============================================================================

func TestHandler_ExecuteTool_Direct(t *testing.T) {
	config := &Config{
		ServerInfo: ServerInfo{Name: "test", Version: "1.0"},
		Tools: []ToolConfig{{
			Name:        "direct_tool",
			InputSchema: json.RawMessage(`{"type":"object"}`),
			Handler: ToolHandler{
				Type:   "static",
				Static: &StaticHandler{Content: `{"direct":true}`},
			},
		}},
	}

	handler, err := NewHandler(config)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	result, execErr := handler.ExecuteTool(context.Background(), "direct_tool", nil)
	if execErr != nil {
		t.Fatalf("ExecuteTool failed: %v", execErr)
	}

	if result.IsError {
		t.Error("Expected no error")
	}

	var content map[string]interface{}
	json.Unmarshal([]byte(result.Content[0].Text), &content)
	if content["direct"] != true {
		t.Errorf("Expected direct=true, got %v", content["direct"])
	}
}

// =============================================================================
// P3: Roots
// =============================================================================

func TestHandler_RootsList(t *testing.T) {
	config := &Config{
		ServerInfo: ServerInfo{Name: "test", Version: "1.0"},
	}

	handler, _ := NewHandler(config)

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"roots/list"}`
	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var resp JSONRPCResponse
	json.NewDecoder(w.Result().Body).Decode(&resp)

	if resp.Error != nil {
		t.Fatalf("Expected no error, got: %v", resp.Error)
	}

	resultMap := resp.Result.(map[string]interface{})
	roots := resultMap["roots"].([]interface{})
	if len(roots) != 0 {
		t.Errorf("Expected empty roots list for HTTP server, got %d", len(roots))
	}
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkToolAuthApply(b *testing.B) {
	b.ReportAllocs()
	provider := NewToolAuthProvider(&ToolAuthConfig{Type: "bearer_token", Token: "test-token"})
	req, _ := http.NewRequest("GET", "https://api.example.com", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider.ApplyAuth(req)
	}
}

func BenchmarkParseLinkHeader(b *testing.B) {
	b.ReportAllocs()
	header := `<https://api.example.com/items?page=1>; rel="prev", <https://api.example.com/items?page=3>; rel="next"`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parseLinkHeader(header, "next")
	}
}

func BenchmarkResolveRefs(b *testing.B) {
	b.ReportAllocs()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		spec := map[string]any{
			"components": map[string]any{
				"schemas": map[string]any{
					"User": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"name": map[string]any{"type": "string"},
						},
					},
				},
			},
			"paths": map[string]any{
				"/users": map[string]any{
					"post": map[string]any{
						"requestBody": map[string]any{
							"content": map[string]any{
								"application/json": map[string]any{
									"schema": map[string]any{"$ref": "#/components/schemas/User"},
								},
							},
						},
					},
				},
			},
		}
		ResolveRefs(spec)
	}
}
