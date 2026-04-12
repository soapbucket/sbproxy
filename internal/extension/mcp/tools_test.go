package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestToolRegistry_Register(t *testing.T) {
	registry := NewToolRegistry()

	t.Run("register tool", func(t *testing.T) {
		tool := ToolConfig{
			Name:        "test_tool",
			Description: "A test tool",
			InputSchema: json.RawMessage(`{"type":"object"}`),
		}
		err := registry.Register(tool)
		if err != nil {
			t.Fatalf("Failed to register: %v", err)
		}
	})

	t.Run("duplicate registration", func(t *testing.T) {
		tool := ToolConfig{
			Name: "test_tool",
		}
		err := registry.Register(tool)
		if err == nil {
			t.Error("Expected error for duplicate registration")
		}
	})

	t.Run("empty name", func(t *testing.T) {
		tool := ToolConfig{}
		err := registry.Register(tool)
		if err == nil {
			t.Error("Expected error for empty name")
		}
	})
}

func TestToolRegistry_Get(t *testing.T) {
	registry := NewToolRegistry()
	registry.Register(ToolConfig{Name: "existing_tool"})

	t.Run("existing tool", func(t *testing.T) {
		tool, err := registry.Get("existing_tool")
		if err != nil {
			t.Fatalf("Failed to get: %v", err)
		}
		if tool.Name != "existing_tool" {
			t.Errorf("Expected name 'existing_tool', got %s", tool.Name)
		}
	})

	t.Run("non-existing tool", func(t *testing.T) {
		_, err := registry.Get("nonexistent")
		if err == nil {
			t.Error("Expected error for nonexistent tool")
		}
	})
}

func TestToolRegistry_List(t *testing.T) {
	registry := NewToolRegistry()
	registry.Register(ToolConfig{Name: "tool1", Description: "First tool"})
	registry.Register(ToolConfig{Name: "tool2", Description: "Second tool"})

	tools := registry.List()

	if len(tools) != 2 {
		t.Fatalf("Expected 2 tools, got %d", len(tools))
	}

	// Verify tool metadata is included
	found1, found2 := false, false
	for _, tool := range tools {
		if tool.Name == "tool1" {
			found1 = true
			if tool.Description != "First tool" {
				t.Error("Tool1 description mismatch")
			}
		}
		if tool.Name == "tool2" {
			found2 = true
		}
	}

	if !found1 || !found2 {
		t.Error("Not all tools found in list")
	}
}

func TestToolRegistry_Has(t *testing.T) {
	registry := NewToolRegistry()
	registry.Register(ToolConfig{Name: "existing"})

	if !registry.Has("existing") {
		t.Error("Expected Has() = true for existing tool")
	}

	if registry.Has("nonexistent") {
		t.Error("Expected Has() = false for nonexistent tool")
	}
}

func TestToolExecutor_Execute_Static(t *testing.T) {
	config := &Config{
		Tools: []ToolConfig{
			{
				Name: "static_tool",
				Handler: ToolHandler{
					Type: "static",
					Static: &StaticHandler{
						Content: `{"message": "hello"}`,
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

	ctx := context.Background()
	result, err := executor.Execute(ctx, "static_tool", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.IsError {
		t.Error("Expected IsError = false")
	}

	if len(result.Content) != 1 {
		t.Fatalf("Expected 1 content item, got %d", len(result.Content))
	}

	// Check content is valid JSON
	var content map[string]interface{}
	if jsonErr := json.Unmarshal([]byte(result.Content[0].Text), &content); jsonErr != nil {
		t.Fatalf("Result is not valid JSON: %v", jsonErr)
	}

	if content["message"] != "hello" {
		t.Errorf("Expected message 'hello', got %v", content["message"])
	}
}

func TestToolExecutor_Execute_Proxy(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	config := &Config{
		Tools: []ToolConfig{
			{
				Name: "proxy_tool",
				Handler: ToolHandler{
					Type: "proxy",
					Proxy: &ProxyHandler{
						URL: server.URL,
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

	ctx := context.Background()
	result, err := executor.Execute(ctx, "proxy_tool", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.IsError {
		t.Errorf("Expected IsError = false, content: %v", result.Content)
	}
}

func TestToolExecutor_Execute_ProxyWithTemplate(t *testing.T) {
	// Create mock server
	var receivedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"path": r.URL.Path})
	}))
	defer server.Close()

	config := &Config{
		Tools: []ToolConfig{
			{
				Name: "template_proxy",
				Handler: ToolHandler{
					Type: "proxy",
					Proxy: &ProxyHandler{
						URL: server.URL + "/items/{{ tool.arguments.id }}",
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

	ctx := context.Background()
	args := map[string]interface{}{"id": "123"}
	result, err := executor.Execute(ctx, "template_proxy", args)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.IsError {
		t.Errorf("Expected IsError = false, content: %v", result.Content)
	}

	if receivedPath != "/items/123" {
		t.Errorf("Expected path '/items/123', got %s", receivedPath)
	}
}

func TestToolExecutor_Execute_Timeout(t *testing.T) {
	// Create slow server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &Config{
		Tools: []ToolConfig{
			{
				Name:    "slow_tool",
				Timeout: reqctx.Duration{Duration: 100 * time.Millisecond},
				Handler: ToolHandler{
					Type: "proxy",
					Proxy: &ProxyHandler{
						URL: server.URL,
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

	ctx := context.Background()
	_, err := executor.Execute(ctx, "slow_tool", nil)
	if err == nil {
		t.Error("Expected timeout error")
	}

	if !err.IsTimeout() {
		t.Errorf("Expected timeout error, got: %v", err)
	}
}

func TestToolExecutor_Execute_ValidationError(t *testing.T) {
	config := &Config{
		Tools: []ToolConfig{
			{
				Name:        "validated_tool",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`),
				Handler: ToolHandler{
					Type: "static",
					Static: &StaticHandler{
						Content: `{}`,
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

	ctx := context.Background()
	// Missing required 'name' argument
	_, err := executor.Execute(ctx, "validated_tool", map[string]interface{}{})
	if err == nil {
		t.Fatal("Expected validation error")
	}

	if err.Code != CodeInvalidParams {
		t.Errorf("Expected code %d, got %d", CodeInvalidParams, err.Code)
	}
}

func TestToolExecutor_Execute_UnknownTool(t *testing.T) {
	config := &Config{
		Tools: []ToolConfig{},
	}

	registry := NewToolRegistry()
	validator, _ := NewSchemaValidator(config.Tools)
	executor := NewToolExecutor(registry, validator, config)

	ctx := context.Background()
	_, err := executor.Execute(ctx, "nonexistent", nil)
	if err == nil {
		t.Fatal("Expected error for unknown tool")
	}

	if err.Code != CodeToolNotFound {
		t.Errorf("Expected code %d, got %d", CodeToolNotFound, err.Code)
	}
}

func TestToolExecutor_Execute_LuaTransform(t *testing.T) {
	config := &Config{
		Tools: []ToolConfig{
			{
				Name: "lua_tool",
				Handler: ToolHandler{
					Type: "static",
					Static: &StaticHandler{
						Content: `{"value": 10}`,
					},
					LuaScript: `
						function modify_json(data, ctx)
							data.doubled = data.value * 2
							return data
						end
					`,
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

	ctx := context.Background()
	result, err := executor.Execute(ctx, "lua_tool", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.IsError {
		t.Errorf("Expected IsError = false, got content: %v", result.Content)
	}

	// Parse result
	var content map[string]interface{}
	if jsonErr := json.Unmarshal([]byte(result.Content[0].Text), &content); jsonErr != nil {
		t.Fatalf("Result is not valid JSON: %v", jsonErr)
	}

	if content["doubled"] != float64(20) {
		t.Errorf("Expected doubled = 20, got %v", content["doubled"])
	}
}

func TestToolExecutor_Execute_ResponseTemplate(t *testing.T) {
	config := &Config{
		Tools: []ToolConfig{
			{
				Name: "template_tool",
				Handler: ToolHandler{
					Type: "static",
					Static: &StaticHandler{
						Content: `{"name": "test"}`,
					},
					ResponseTemplate: "Name: {{ result.name }}",
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

	ctx := context.Background()
	result, err := executor.Execute(ctx, "template_tool", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Content[0].Text != "Name: test" {
		t.Errorf("Expected 'Name: test', got %s", result.Content[0].Text)
	}
}

func TestToolExecutor_Execute_ProxyError(t *testing.T) {
	// Create error server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	config := &Config{
		Tools: []ToolConfig{
			{
				Name: "error_tool",
				Handler: ToolHandler{
					Type: "proxy",
					Proxy: &ProxyHandler{
						URL: server.URL,
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

	ctx := context.Background()
	_, err := executor.Execute(ctx, "error_tool", nil)
	if err == nil {
		t.Error("Expected error for 500 response")
	}
}

func TestToolExecutor_Execute_StaticWithResponseTemplateArguments(t *testing.T) {
	config := &Config{
		Tools: []ToolConfig{
			{
				Name:        "delete_simulator",
				Description: "Simulates deletion (dry run)",
				InputSchema: json.RawMessage(`{
					"type": "object",
					"properties": {
						"post_id": {"type": "integer", "description": "Post ID"}
					},
					"required": ["post_id"]
				}`),
				Handler: ToolHandler{
					Type:             "static",
					Static:           &StaticHandler{Content: ""},
					ResponseTemplate: "DRY RUN: Delete Post #{{ tool.arguments.post_id }}\nStatus: simulated_success",
				},
			},
		},
	}

	registry := NewToolRegistry()
	for _, tool := range config.Tools {
		if err := registry.Register(tool); err != nil {
			t.Fatal(err)
		}
	}

	validator, err := NewSchemaValidator(config.Tools)
	if err != nil {
		t.Fatal(err)
	}
	executor := NewToolExecutor(registry, validator, config)

	ctx := context.Background()
	args := map[string]interface{}{
		"post_id": float64(42),
	}

	result, execErr := executor.Execute(ctx, "delete_simulator", args)
	if execErr != nil {
		t.Fatalf("Unexpected error: %v", execErr)
	}

	if result.IsError {
		t.Errorf("Expected IsError = false")
	}

	if len(result.Content) != 1 {
		t.Fatalf("Expected 1 content item, got %d", len(result.Content))
	}

	text := result.Content[0].Text

	if !strings.Contains(text, "Post #42") {
		t.Errorf("Expected 'Post #42' in output, got: %s", text)
	}

	if !strings.Contains(text, "simulated_success") {
		t.Errorf("Expected 'simulated_success' in output (full render), got: %s", text)
	}
}

// =============================================================================
// Origin Proxy Tests
// =============================================================================

func TestExecuteOriginProxy_Basic(t *testing.T) {
	// Mock origin handler returns JSON
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"result": "from-origin"})
	})

	config := &Config{
		Tools: []ToolConfig{
			{
				Name: "origin_tool",
				Handler: ToolHandler{
					Type: "proxy",
					Proxy: &ProxyHandler{
						OriginHost:            "example.origin.test",
						resolvedOriginHandler: mockHandler,
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

	ctx := context.Background()
	result, err := executor.Execute(ctx, "origin_tool", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.IsError {
		t.Errorf("Expected IsError = false")
	}

	var content map[string]interface{}
	if jsonErr := json.Unmarshal([]byte(result.Content[0].Text), &content); jsonErr != nil {
		t.Fatalf("Result is not valid JSON: %v", jsonErr)
	}

	if content["result"] != "from-origin" {
		t.Errorf("Expected result 'from-origin', got %v", content["result"])
	}
}

func TestExecuteOriginProxy_HTMLToMarkdown(t *testing.T) {
	// Mock origin handler returns markdown (simulating html_to_markdown transform)
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/markdown")
		w.Write([]byte("# Hello World\n\nThis is markdown content."))
	})

	config := &Config{
		Tools: []ToolConfig{
			{
				Name: "markdown_tool",
				Handler: ToolHandler{
					Type: "proxy",
					Proxy: &ProxyHandler{
						OriginConfig:          json.RawMessage(`{"action":{"type":"proxy","url":"https://example.com"}}`),
						resolvedOriginHandler: mockHandler,
						ContentType:           "text",
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

	ctx := context.Background()
	result, err := executor.Execute(ctx, "markdown_tool", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.IsError {
		t.Errorf("Expected IsError = false")
	}

	text := result.Content[0].Text
	if !strings.Contains(text, "# Hello World") {
		t.Errorf("Expected markdown content, got: %s", text)
	}
}

func TestExecuteOriginProxy_WithHeaders(t *testing.T) {
	var receivedAuth string
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
	})

	config := &Config{
		Tools: []ToolConfig{
			{
				Name: "header_tool",
				Handler: ToolHandler{
					Type: "proxy",
					Proxy: &ProxyHandler{
						OriginHost:            "api.test",
						resolvedOriginHandler: mockHandler,
						Headers: map[string]string{
							"Authorization": "Bearer test-token",
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

	ctx := context.Background()
	result, err := executor.Execute(ctx, "header_tool", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.IsError {
		t.Errorf("Expected IsError = false")
	}

	if receivedAuth != "Bearer test-token" {
		t.Errorf("Expected Authorization header 'Bearer test-token', got %q", receivedAuth)
	}
}

func TestExecuteOriginProxy_WithBody(t *testing.T) {
	var receivedBody string
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"received": "true"})
	})

	config := &Config{
		Tools: []ToolConfig{
			{
				Name:        "body_tool",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"message":{"type":"string"}}}`),
				Handler: ToolHandler{
					Type: "proxy",
					Proxy: &ProxyHandler{
						OriginHost:            "api.test",
						Method:                "POST",
						resolvedOriginHandler: mockHandler,
						BodyTemplate: map[string]interface{}{
							"text": "{{ tool.arguments.message }}",
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

	ctx := context.Background()
	args := map[string]interface{}{"message": "hello world"}
	result, err := executor.Execute(ctx, "body_tool", args)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.IsError {
		t.Errorf("Expected IsError = false")
	}

	// Verify body was sent
	var bodyData map[string]interface{}
	if jsonErr := json.Unmarshal([]byte(receivedBody), &bodyData); jsonErr != nil {
		t.Fatalf("Body is not valid JSON: %v (body: %s)", jsonErr, receivedBody)
	}

	if bodyData["text"] != "hello world" {
		t.Errorf("Expected body text 'hello world', got %v", bodyData["text"])
	}
}

func TestExecuteOriginProxy_ErrorMapping(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	})

	config := &Config{
		Tools: []ToolConfig{
			{
				Name: "error_origin_tool",
				Handler: ToolHandler{
					Type: "proxy",
					Proxy: &ProxyHandler{
						OriginHost:            "api.test",
						resolvedOriginHandler: mockHandler,
						ErrorMapping: map[string]string{
							"404": "Resource not found",
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

	ctx := context.Background()
	_, err := executor.Execute(ctx, "error_origin_tool", nil)
	if err == nil {
		t.Fatal("Expected error for 404 response")
	}

	// Error should be mapped to user-friendly message
	if !strings.Contains(err.Message, "Resource not found") {
		t.Errorf("Expected mapped error message, got: %s", err.Message)
	}
}

func TestExecuteOriginProxy_BackwardCompat(t *testing.T) {
	// Verify url-only tools still work unchanged
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	config := &Config{
		Tools: []ToolConfig{
			{
				Name: "url_tool",
				Handler: ToolHandler{
					Type: "proxy",
					Proxy: &ProxyHandler{
						URL: server.URL,
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

	ctx := context.Background()
	result, err := executor.Execute(ctx, "url_tool", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.IsError {
		t.Errorf("Expected IsError = false")
	}

	var content map[string]interface{}
	if jsonErr := json.Unmarshal([]byte(result.Content[0].Text), &content); jsonErr != nil {
		t.Fatalf("Result is not valid JSON: %v", jsonErr)
	}

	if content["status"] != "ok" {
		t.Errorf("Expected status 'ok', got %v", content["status"])
	}
}

func TestValidateProxyHandlerSource_MutualExclusion(t *testing.T) {
	tests := []struct {
		name    string
		handler *ProxyHandler
		wantErr bool
	}{
		{
			name:    "url only - valid",
			handler: &ProxyHandler{URL: "https://example.com"},
			wantErr: false,
		},
		{
			name:    "origin_host only - valid",
			handler: &ProxyHandler{OriginHost: "example.test"},
			wantErr: false,
		},
		{
			name:    "origin_config only - valid",
			handler: &ProxyHandler{OriginConfig: json.RawMessage(`{"action":{"type":"proxy"}}`)},
			wantErr: false,
		},
		{
			name:    "none set - invalid",
			handler: &ProxyHandler{},
			wantErr: true,
		},
		{
			name:    "url and origin_host - invalid",
			handler: &ProxyHandler{URL: "https://example.com", OriginHost: "example.test"},
			wantErr: true,
		},
		{
			name:    "url and origin_config - invalid",
			handler: &ProxyHandler{URL: "https://example.com", OriginConfig: json.RawMessage(`{}`)},
			wantErr: true,
		},
		{
			name:    "origin_host and origin_config - invalid",
			handler: &ProxyHandler{OriginHost: "example.test", OriginConfig: json.RawMessage(`{}`)},
			wantErr: true,
		},
		{
			name:    "all three set - invalid",
			handler: &ProxyHandler{URL: "https://example.com", OriginHost: "example.test", OriginConfig: json.RawMessage(`{}`)},
			wantErr: true,
		},
		{
			name:    "nil handler - invalid",
			handler: nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProxyHandlerSource(tt.handler)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateProxyHandlerSource() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExecuteOriginProxy_ResponseMapping(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"user": map[string]interface{}{
					"name":  "Alice",
					"email": "alice@example.com",
				},
			},
		})
	})

	config := &Config{
		Tools: []ToolConfig{
			{
				Name: "mapping_tool",
				Handler: ToolHandler{
					Type: "proxy",
					Proxy: &ProxyHandler{
						OriginHost:            "api.test",
						resolvedOriginHandler: mockHandler,
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

	ctx := context.Background()
	result, err := executor.Execute(ctx, "mapping_tool", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	var content map[string]interface{}
	if jsonErr := json.Unmarshal([]byte(result.Content[0].Text), &content); jsonErr != nil {
		t.Fatalf("Result is not valid JSON: %v", jsonErr)
	}

	if content["name"] != "Alice" {
		t.Errorf("Expected name 'Alice', got %v", content["name"])
	}
	if content["email"] != "alice@example.com" {
		t.Errorf("Expected email 'alice@example.com', got %v", content["email"])
	}
}

func TestProxyHandler_HasOriginRouting(t *testing.T) {
	// URL-only handler should not have origin routing
	h1 := &ProxyHandler{URL: "https://example.com"}
	if h1.HasOriginRouting() {
		t.Error("URL-only handler should not have origin routing")
	}

	// OriginHost handler should have origin routing
	h2 := &ProxyHandler{OriginHost: "example.test"}
	if !h2.HasOriginRouting() {
		t.Error("OriginHost handler should have origin routing")
	}

	// OriginConfig handler should have origin routing
	h3 := &ProxyHandler{OriginConfig: json.RawMessage(`{}`)}
	if !h3.HasOriginRouting() {
		t.Error("OriginConfig handler should have origin routing")
	}

	// Nil handler should not have origin routing
	var h4 *ProxyHandler
	if h4.HasOriginRouting() {
		t.Error("Nil handler should not have origin routing")
	}
}
