package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// =============================================================================
// Handler Tests
// =============================================================================

func TestHandler_Initialize(t *testing.T) {
	handler := createTestHandler(t)

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test-client","version":"1.0"}}}`

	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result JSONRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if result.Error != nil {
		t.Errorf("Unexpected error: %v", result.Error)
	}

	if result.ID != float64(1) {
		t.Errorf("Expected ID 1, got %v", result.ID)
	}

	initResult, ok := result.Result.(*InitializeResult)
	if !ok {
		// Result comes as map from JSON
		resultMap, ok := result.Result.(map[string]interface{})
		if !ok {
			t.Fatalf("Expected InitializeResult or map, got %T", result.Result)
		}
		if resultMap["protocolVersion"] != ProtocolVersion {
			t.Errorf("Expected protocol version %s, got %v", ProtocolVersion, resultMap["protocolVersion"])
		}
	} else {
		if initResult.ProtocolVersion != ProtocolVersion {
			t.Errorf("Expected protocol version %s, got %s", ProtocolVersion, initResult.ProtocolVersion)
		}
	}
}

func TestHandler_ToolsList(t *testing.T) {
	handler := createTestHandler(t)

	reqBody := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`

	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result JSONRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if result.Error != nil {
		t.Errorf("Unexpected error: %v", result.Error)
	}

	resultMap, ok := result.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map result, got %T", result.Result)
	}

	tools, ok := resultMap["tools"].([]interface{})
	if !ok {
		t.Fatalf("Expected tools array, got %T", resultMap["tools"])
	}

	if len(tools) != 2 {
		t.Errorf("Expected 2 tools, got %d", len(tools))
	}
}

func TestHandler_ToolsCall_Static(t *testing.T) {
	handler := createTestHandler(t)

	reqBody := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello"}}}`

	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d, body: %s", resp.StatusCode, string(body))
	}

	var result JSONRPCResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if result.Error != nil {
		t.Errorf("Unexpected error: %v", result.Error)
	}

	// Check tool result
	resultMap, ok := result.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map result, got %T", result.Result)
	}

	if resultMap["isError"] == true {
		t.Errorf("Tool returned error: %v", resultMap)
	}
}

func TestHandler_ToolsCall_UnknownTool(t *testing.T) {
	handler := createTestHandler(t)

	reqBody := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"unknown_tool","arguments":{}}}`

	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	var result JSONRPCResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Should be a protocol error (tool not found)
	if result.Error == nil {
		t.Error("Expected error for unknown tool")
	}

	if result.Error.Code != CodeToolNotFound {
		t.Errorf("Expected code %d, got %d", CodeToolNotFound, result.Error.Code)
	}
}

func TestHandler_ToolsCall_ValidationError(t *testing.T) {
	handler := createTestHandler(t)

	// Missing required 'value' parameter
	reqBody := `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"add","arguments":{"wrong_param":"test"}}}`

	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	var result JSONRPCResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Should be a validation error
	if result.Error == nil {
		t.Error("Expected validation error")
	}

	if result.Error.Code != CodeInvalidParams {
		t.Errorf("Expected code %d, got %d", CodeInvalidParams, result.Error.Code)
	}
}

func TestHandler_MethodNotFound(t *testing.T) {
	handler := createTestHandler(t)

	reqBody := `{"jsonrpc":"2.0","id":6,"method":"unknown/method"}`

	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	var result JSONRPCResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if result.Error == nil {
		t.Error("Expected error for unknown method")
	}

	if result.Error.Code != CodeMethodNotFound {
		t.Errorf("Expected code %d, got %d", CodeMethodNotFound, result.Error.Code)
	}
}

func TestHandler_InvalidJSON(t *testing.T) {
	handler := createTestHandler(t)

	reqBody := `{invalid json}`

	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	var result JSONRPCResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if result.Error == nil {
		t.Error("Expected parse error")
	}

	if result.Error.Code != CodeParseError {
		t.Errorf("Expected code %d, got %d", CodeParseError, result.Error.Code)
	}
}

func TestHandler_InvalidRequest_MissingMethod(t *testing.T) {
	handler := createTestHandler(t)

	reqBody := `{"jsonrpc":"2.0","id":7}`

	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	var result JSONRPCResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if result.Error == nil {
		t.Error("Expected invalid request error")
	}

	if result.Error.Code != CodeInvalidRequest {
		t.Errorf("Expected code %d, got %d", CodeInvalidRequest, result.Error.Code)
	}
}

func TestHandler_InvalidRequest_WrongVersion(t *testing.T) {
	handler := createTestHandler(t)

	reqBody := `{"jsonrpc":"1.0","id":8,"method":"tools/list"}`

	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	var result JSONRPCResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if result.Error == nil {
		t.Error("Expected invalid request error for wrong version")
	}

	if result.Error.Code != CodeInvalidRequest {
		t.Errorf("Expected code %d, got %d", CodeInvalidRequest, result.Error.Code)
	}
}

func TestHandler_Notification(t *testing.T) {
	handler := createTestHandler(t)

	// Notification has no ID
	reqBody := `{"jsonrpc":"2.0","method":"initialized"}`

	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("Expected status 204 for notification, got %d", resp.StatusCode)
	}
}

func TestHandler_Ping(t *testing.T) {
	handler := createTestHandler(t)

	reqBody := `{"jsonrpc":"2.0","id":9,"method":"ping"}`

	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	var result JSONRPCResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if result.Error != nil {
		t.Errorf("Unexpected error: %v", result.Error)
	}
}

func TestHandler_ResourcesList(t *testing.T) {
	handler := createTestHandler(t)

	reqBody := `{"jsonrpc":"2.0","id":10,"method":"resources/list"}`

	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	var result JSONRPCResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if result.Error != nil {
		t.Errorf("Unexpected error: %v", result.Error)
	}

	resultMap, ok := result.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map result, got %T", result.Result)
	}

	resources, ok := resultMap["resources"].([]interface{})
	if !ok {
		t.Fatalf("Expected resources array, got %T", resultMap["resources"])
	}

	if len(resources) != 1 {
		t.Errorf("Expected 1 resource, got %d", len(resources))
	}
}

func TestHandler_ResourcesRead(t *testing.T) {
	handler := createTestHandler(t)

	reqBody := `{"jsonrpc":"2.0","id":11,"method":"resources/read","params":{"uri":"resource://config"}}`

	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	var result JSONRPCResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if result.Error != nil {
		t.Errorf("Unexpected error: %v", result.Error)
	}
}

func TestHandler_ResourcesRead_NotFound(t *testing.T) {
	handler := createTestHandler(t)

	reqBody := `{"jsonrpc":"2.0","id":12,"method":"resources/read","params":{"uri":"resource://unknown"}}`

	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	var result JSONRPCResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if result.Error == nil {
		t.Error("Expected error for unknown resource")
	}
}

// =============================================================================
// Test Helpers
// =============================================================================

func createTestHandler(t *testing.T) *Handler {
	t.Helper()

	config := &Config{
		ServerInfo: ServerInfo{
			Name:    "test-mcp-server",
			Version: "1.0.0",
		},
		Capabilities: Capabilities{
			Tools: &ToolsCapability{},
		},
		Tools: []ToolConfig{
			{
				Name:        "echo",
				Description: "Echoes back the message",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"message":{"type":"string"}}}`),
				Handler: ToolHandler{
					Type: "static",
					Static: &StaticHandler{
						Content: `{"echo": "response"}`,
					},
				},
			},
			{
				Name:        "add",
				Description: "Adds two numbers",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"value":{"type":"number"}},"required":["value"]}`),
				Handler: ToolHandler{
					Type: "static",
					Static: &StaticHandler{
						Content: `{"result": 42}`,
					},
				},
			},
		},
		Resources: []ResourceConfig{
			{
				URI:         "resource://config",
				Name:        "Configuration",
				Description: "Test configuration",
				MimeType:    "application/json",
				Handler: ResourceHandler{
					Type: "static",
					Static: &StaticHandler{
						Content: `{"version": "1.0"}`,
					},
				},
			},
		},
	}

	handler, err := NewHandler(config)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	return handler
}
