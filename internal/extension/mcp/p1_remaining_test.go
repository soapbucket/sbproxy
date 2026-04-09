package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// =============================================================================
// Gateway Mode
// =============================================================================

func TestGatewayHandler_ToolsList(t *testing.T) {
	// Create upstream MCP server
	upstreamTools := ListToolsResult{
		Tools: []Tool{
			{Name: "search", Description: "Search things", InputSchema: json.RawMessage(`{"type":"object"}`)},
			{Name: "lookup", Description: "Lookup by ID", InputSchema: json.RawMessage(`{"type":"object"}`)},
		},
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		json.NewDecoder(r.Body).Decode(&req)

		switch req.Method {
		case "tools/list":
			resp := JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: &upstreamTools}
			json.NewEncoder(w).Encode(resp)
		case "tools/call":
			result := &ToolResult{
				Content: []Content{{Type: "text", Text: `{"found": true}`}},
			}
			resp := JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
			json.NewEncoder(w).Encode(resp)
		}
	}))
	defer upstream.Close()

	config := &Config{
		Mode:         ModeGateway,
		ServerInfo:   ServerInfo{Name: "gateway-test", Version: "1.0"},
		Capabilities: Capabilities{Tools: &ToolsCapability{}},
		FederatedServers: []FederatedServerConfig{
			{URL: upstream.URL, Prefix: "svc"},
		},
	}

	handler, err := NewGatewayHandler(config)
	if err != nil {
		t.Fatalf("Failed to create gateway handler: %v", err)
	}
	if err := handler.Init(context.Background()); err != nil {
		t.Fatalf("Failed to init gateway: %v", err)
	}

	// Test tools/list
	listBody := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	listReq := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(listBody))
	listW := httptest.NewRecorder()
	handler.ServeHTTP(listW, listReq)

	var listResp JSONRPCResponse
	json.NewDecoder(listW.Result().Body).Decode(&listResp)

	resultMap := listResp.Result.(map[string]interface{})
	tools := resultMap["tools"].([]interface{})
	if len(tools) != 2 {
		t.Fatalf("Expected 2 tools, got %d", len(tools))
	}
}

func TestGatewayHandler_ToolsCall_Forwards(t *testing.T) {
	var receivedToolName string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		json.NewDecoder(r.Body).Decode(&req)

		switch req.Method {
		case "tools/list":
			tools := ListToolsResult{
				Tools: []Tool{{Name: "echo", InputSchema: json.RawMessage(`{"type":"object"}`)}},
			}
			json.NewEncoder(w).Encode(JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: &tools})
		case "tools/call":
			var params ToolCallParams
			json.Unmarshal(req.Params, &params)
			receivedToolName = params.Name

			result := &ToolResult{
				Content: []Content{{Type: "text", Text: `{"echoed": true}`}},
			}
			json.NewEncoder(w).Encode(JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result})
		}
	}))
	defer upstream.Close()

	config := &Config{
		Mode:         ModeGateway,
		ServerInfo:   ServerInfo{Name: "gw", Version: "1.0"},
		Capabilities: Capabilities{Tools: &ToolsCapability{}},
		FederatedServers: []FederatedServerConfig{
			{URL: upstream.URL},
		},
	}

	handler, _ := NewGatewayHandler(config)
	handler.Init(context.Background())

	callBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hi"}}}`
	callReq := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(callBody))
	callW := httptest.NewRecorder()
	handler.ServeHTTP(callW, callReq)

	var callResp JSONRPCResponse
	json.NewDecoder(callW.Result().Body).Decode(&callResp)

	if callResp.Error != nil {
		t.Fatalf("Expected no error, got: %v", callResp.Error)
	}

	if receivedToolName != "echo" {
		t.Errorf("Expected upstream to receive tool name 'echo', got %q", receivedToolName)
	}
}

func TestGatewayHandler_Initialize(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tools := ListToolsResult{Tools: []Tool{}}
		json.NewEncoder(w).Encode(JSONRPCResponse{JSONRPC: "2.0", ID: 1, Result: &tools})
	}))
	defer upstream.Close()

	config := &Config{
		Mode:         ModeGateway,
		ServerInfo:   ServerInfo{Name: "my-gateway", Version: "2.0"},
		Capabilities: Capabilities{Tools: &ToolsCapability{}},
		FederatedServers: []FederatedServerConfig{{URL: upstream.URL}},
	}

	handler, _ := NewGatewayHandler(config)
	handler.Init(context.Background())

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"test","version":"1.0"}}}`
	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var resp JSONRPCResponse
	json.NewDecoder(w.Result().Body).Decode(&resp)

	resultMap := resp.Result.(map[string]interface{})
	serverInfo := resultMap["serverInfo"].(map[string]interface{})
	if serverInfo["name"] != "my-gateway" {
		t.Errorf("Expected server name 'my-gateway', got %v", serverInfo["name"])
	}
}

func TestGatewayHandler_RequiresFederatedServers(t *testing.T) {
	_, err := NewGatewayHandler(&Config{Mode: ModeGateway})
	if err == nil {
		t.Error("Expected error when no federated servers configured")
	}
}

// =============================================================================
// Prompts
// =============================================================================

func TestPromptRegistry_RegisterAndGet(t *testing.T) {
	registry := NewPromptRegistry()

	err := registry.Register(PromptConfig{
		Name:        "summarize",
		Description: "Summarize a ticket",
		Arguments: []PromptArgument{
			{Name: "ticket_id", Required: true},
		},
		Messages: []PromptMessage{
			{Role: "user", Content: "Summarize ticket #{{ arguments.ticket_id }}"},
		},
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	prompts := registry.List()
	if len(prompts) != 1 {
		t.Fatalf("Expected 1 prompt, got %d", len(prompts))
	}

	prompt, getErr := registry.Get("summarize")
	if getErr != nil {
		t.Fatalf("Get failed: %v", getErr)
	}
	if prompt.Name != "summarize" {
		t.Errorf("Expected name 'summarize', got %s", prompt.Name)
	}
}

func TestPromptRegistry_DuplicateName(t *testing.T) {
	registry := NewPromptRegistry()
	registry.Register(PromptConfig{Name: "test"})

	err := registry.Register(PromptConfig{Name: "test"})
	if err == nil {
		t.Error("Expected error for duplicate name")
	}
}

func TestRenderPrompt(t *testing.T) {
	prompt := &PromptConfig{
		Name: "greet",
		Arguments: []PromptArgument{
			{Name: "name", Required: true},
		},
		Messages: []PromptMessage{
			{Role: "user", Content: "Hello {{ arguments.name }}, how are you?"},
		},
	}

	result, err := RenderPrompt(context.Background(), prompt, map[string]string{"name": "Alice"})
	if err != nil {
		t.Fatalf("RenderPrompt failed: %v", err)
	}

	if len(result.Messages) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(result.Messages))
	}

	if result.Messages[0].Content.Text != "Hello Alice, how are you?" {
		t.Errorf("Expected rendered message, got: %s", result.Messages[0].Content.Text)
	}
	if result.Messages[0].Role != "user" {
		t.Errorf("Expected role 'user', got %s", result.Messages[0].Role)
	}
}

func TestRenderPrompt_MissingRequiredArg(t *testing.T) {
	prompt := &PromptConfig{
		Name: "test",
		Arguments: []PromptArgument{
			{Name: "required_arg", Required: true},
		},
		Messages: []PromptMessage{
			{Role: "user", Content: "{{ arguments.required_arg }}"},
		},
	}

	_, err := RenderPrompt(context.Background(), prompt, map[string]string{})
	if err == nil {
		t.Error("Expected error for missing required argument")
	}
}

func TestHandler_PromptsList(t *testing.T) {
	config := &Config{
		ServerInfo:   ServerInfo{Name: "test", Version: "1.0"},
		Capabilities: Capabilities{Prompts: &PromptsCapability{}},
		Prompts: []PromptConfig{
			{
				Name:        "summarize",
				Description: "Summarize text",
				Arguments: []PromptArgument{
					{Name: "text", Required: true},
				},
				Messages: []PromptMessage{
					{Role: "user", Content: "Summarize: {{ arguments.text }}"},
				},
			},
		},
	}

	handler, err := NewHandler(config)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"prompts/list"}`
	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var resp JSONRPCResponse
	json.NewDecoder(w.Result().Body).Decode(&resp)

	if resp.Error != nil {
		t.Fatalf("Expected no error, got: %v", resp.Error)
	}

	resultMap := resp.Result.(map[string]interface{})
	prompts := resultMap["prompts"].([]interface{})
	if len(prompts) != 1 {
		t.Fatalf("Expected 1 prompt, got %d", len(prompts))
	}
}

func TestHandler_PromptsGet(t *testing.T) {
	config := &Config{
		ServerInfo:   ServerInfo{Name: "test", Version: "1.0"},
		Capabilities: Capabilities{Prompts: &PromptsCapability{}},
		Prompts: []PromptConfig{
			{
				Name: "greet",
				Arguments: []PromptArgument{
					{Name: "name", Required: true},
				},
				Messages: []PromptMessage{
					{Role: "user", Content: "Hello {{ arguments.name }}!"},
				},
			},
		},
	}

	handler, err := NewHandler(config)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"greet","arguments":{"name":"Bob"}}}`
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
	messages := resultMap["messages"].([]interface{})
	if len(messages) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(messages))
	}

	msg := messages[0].(map[string]interface{})
	content := msg["content"].(map[string]interface{})
	if content["text"] != "Hello Bob!" {
		t.Errorf("Expected 'Hello Bob!', got %v", content["text"])
	}
}

// =============================================================================
// Tool Result Caching
// =============================================================================

func TestToolResultCache_PutGet(t *testing.T) {
	cache := NewToolResultCache(&ToolCacheConfig{
		Enabled:    true,
		DefaultTTL: reqctx.Duration{Duration: 5 * time.Minute},
		MaxEntries: 100,
	})

	result := &ToolResult{
		Content: []Content{{Type: "text", Text: "cached"}},
	}

	cache.Put("key1", result, 1*time.Minute)

	got, ok := cache.Get("key1")
	if !ok {
		t.Fatal("Expected cache hit")
	}
	if got.Content[0].Text != "cached" {
		t.Errorf("Expected 'cached', got %s", got.Content[0].Text)
	}
}

func TestToolResultCache_Expiration(t *testing.T) {
	cache := NewToolResultCache(&ToolCacheConfig{
		Enabled:    true,
		DefaultTTL: reqctx.Duration{Duration: 10 * time.Millisecond},
		MaxEntries: 100,
	})

	result := &ToolResult{
		Content: []Content{{Type: "text", Text: "expires"}},
	}

	cache.Put("key1", result, 10*time.Millisecond)

	time.Sleep(20 * time.Millisecond)

	_, ok := cache.Get("key1")
	if ok {
		t.Error("Expected cache miss after expiration")
	}
}

func TestToolResultCache_MaxEntries(t *testing.T) {
	cache := NewToolResultCache(&ToolCacheConfig{
		Enabled:    true,
		DefaultTTL: reqctx.Duration{Duration: 5 * time.Minute},
		MaxEntries: 3,
	})

	for i := 0; i < 5; i++ {
		result := &ToolResult{Content: []Content{{Type: "text", Text: "v"}}}
		cache.Put("key"+string(rune('0'+i)), result, 5*time.Minute)
	}

	if cache.Size() > 3 {
		t.Errorf("Expected max 3 entries, got %d", cache.Size())
	}
}

func TestToolResultCache_Nil(t *testing.T) {
	var cache *ToolResultCache
	_, ok := cache.Get("key")
	if ok {
		t.Error("Expected miss on nil cache")
	}
	cache.Put("key", &ToolResult{}, time.Minute) // Should not panic
	cache.Delete("key")                           // Should not panic
	cache.Clear()                                  // Should not panic
}

func TestBuildCacheKey_Scopes(t *testing.T) {
	args := map[string]interface{}{"q": "test"}

	t.Run("shared", func(t *testing.T) {
		key := BuildCacheKey(context.Background(), "search", args, &ToolCacheEntry{Scope: "shared"})
		if key == "" {
			t.Error("Expected non-empty key")
		}
	})

	t.Run("per_user", func(t *testing.T) {
		ctx := ContextWithIdentity(context.Background(), []string{"admin"}, "")
		key1 := BuildCacheKey(ctx, "search", args, &ToolCacheEntry{Scope: "per_user"})

		ctx2 := ContextWithIdentity(context.Background(), []string{"viewer"}, "")
		key2 := BuildCacheKey(ctx2, "search", args, &ToolCacheEntry{Scope: "per_user"})

		if key1 == key2 {
			t.Error("Expected different keys for different users")
		}
	})

	t.Run("per_key", func(t *testing.T) {
		ctx := ContextWithIdentity(context.Background(), nil, "key-a")
		key1 := BuildCacheKey(ctx, "search", args, &ToolCacheEntry{Scope: "per_key"})

		ctx2 := ContextWithIdentity(context.Background(), nil, "key-b")
		key2 := BuildCacheKey(ctx2, "search", args, &ToolCacheEntry{Scope: "per_key"})

		if key1 == key2 {
			t.Error("Expected different keys for different API keys")
		}
	})
}

func TestHandler_ToolCaching_Integration(t *testing.T) {
	callCount := 0

	config := &Config{
		ServerInfo:   ServerInfo{Name: "test", Version: "1.0"},
		Capabilities: Capabilities{Tools: &ToolsCapability{}},
		ToolCache:    &ToolCacheConfig{Enabled: true, DefaultTTL: reqctx.Duration{Duration: 5 * time.Minute}, MaxEntries: 100},
		Tools: []ToolConfig{
			{
				Name:        "counter",
				InputSchema: json.RawMessage(`{"type":"object"}`),
				Handler: ToolHandler{
					Type:   "static",
					Static: &StaticHandler{Content: `{"count": 1}`},
				},
				Cache: &ToolCacheEntry{TTL: reqctx.Duration{Duration: 5 * time.Minute}},
			},
		},
	}

	handler, err := NewHandler(config)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	// Call twice - second should be cached
	for i := 0; i < 2; i++ {
		callCount++
		reqBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"counter","arguments":{}}}`
		req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		var resp JSONRPCResponse
		json.NewDecoder(w.Result().Body).Decode(&resp)
		if resp.Error != nil {
			t.Fatalf("Call %d failed: %v", i, resp.Error)
		}
	}

	// Verify cache has an entry
	if handler.toolCache.Size() != 1 {
		t.Errorf("Expected 1 cached entry, got %d", handler.toolCache.Size())
	}
}

// =============================================================================
// Logging
// =============================================================================

func TestHandler_LoggingSetLevel(t *testing.T) {
	config := &Config{
		ServerInfo:   ServerInfo{Name: "test", Version: "1.0"},
		Capabilities: Capabilities{},
	}

	handler, _ := NewHandler(config)

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"logging/setLevel","params":{"level":"debug"}}`
	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var resp JSONRPCResponse
	json.NewDecoder(w.Result().Body).Decode(&resp)

	if resp.Error != nil {
		t.Fatalf("Expected no error, got: %v", resp.Error)
	}

	if handler.config.LogLevel != "debug" {
		t.Errorf("Expected log level 'debug', got %s", handler.config.LogLevel)
	}
}

func TestHandler_LoggingSetLevel_InvalidLevel(t *testing.T) {
	config := &Config{
		ServerInfo:   ServerInfo{Name: "test", Version: "1.0"},
		Capabilities: Capabilities{},
	}

	handler, _ := NewHandler(config)

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"logging/setLevel","params":{"level":"invalid"}}`
	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var resp JSONRPCResponse
	body, _ := io.ReadAll(w.Result().Body)
	json.Unmarshal(body, &resp)

	if resp.Error == nil {
		t.Error("Expected error for invalid log level")
	}
}

// =============================================================================
// Orchestrator Mode (formalization)
// =============================================================================

func TestConfig_DefaultMode(t *testing.T) {
	config := &Config{}
	// Default mode should be treated as orchestrator
	if config.Mode != "" {
		t.Errorf("Expected empty default mode, got %s", config.Mode)
	}
	// Empty mode is treated as orchestrator - existing behavior
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkToolResultCache_PutGet(b *testing.B) {
	b.ReportAllocs()

	cache := NewToolResultCache(&ToolCacheConfig{
		Enabled:    true,
		DefaultTTL: reqctx.Duration{Duration: 5 * time.Minute},
		MaxEntries: 10000,
	})

	result := &ToolResult{Content: []Content{{Type: "text", Text: "cached"}}}
	cache.Put("bench_key", result, 5*time.Minute)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get("bench_key")
	}
}

func BenchmarkBuildCacheKey(b *testing.B) {
	b.ReportAllocs()

	args := map[string]interface{}{"q": "test", "limit": 10}
	entry := &ToolCacheEntry{Scope: "shared"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BuildCacheKey(context.Background(), "search", args, entry)
	}
}

func BenchmarkGatewayToolsList(b *testing.B) {
	b.ReportAllocs()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tools := ListToolsResult{
			Tools: []Tool{
				{Name: "t1", InputSchema: json.RawMessage(`{"type":"object"}`)},
				{Name: "t2", InputSchema: json.RawMessage(`{"type":"object"}`)},
			},
		}
		json.NewEncoder(w).Encode(JSONRPCResponse{JSONRPC: "2.0", ID: 1, Result: &tools})
	}))
	defer upstream.Close()

	config := &Config{
		Mode:         ModeGateway,
		ServerInfo:   ServerInfo{Name: "bench", Version: "1.0"},
		Capabilities: Capabilities{Tools: &ToolsCapability{}},
		FederatedServers: []FederatedServerConfig{{URL: upstream.URL}},
	}

	handler, _ := NewGatewayHandler(config)
	handler.Init(context.Background())

	reqBody := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/mcp", bytes.NewReader(reqBody))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}
