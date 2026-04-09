package mcp

import (
	"encoding/json"
	"testing"
)

func TestParseJSONRPCRequest(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		data := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
		req, err := ParseJSONRPCRequest(data)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if req.JSONRPC != "2.0" {
			t.Errorf("Expected jsonrpc '2.0', got %s", req.JSONRPC)
		}
		if req.Method != "tools/list" {
			t.Errorf("Expected method 'tools/list', got %s", req.Method)
		}
	})

	t.Run("empty body", func(t *testing.T) {
		_, err := ParseJSONRPCRequest([]byte{})
		if err == nil {
			t.Error("Expected error for empty body")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_, err := ParseJSONRPCRequest([]byte(`{invalid`))
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
		if err.Code != CodeParseError {
			t.Errorf("Expected code %d, got %d", CodeParseError, err.Code)
		}
	})

	t.Run("request with params", func(t *testing.T) {
		data := []byte(`{"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"name":"test","arguments":{}}}`)
		req, err := ParseJSONRPCRequest(data)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if req.Params == nil {
			t.Error("Expected params to be set")
		}
	})

	t.Run("string ID", func(t *testing.T) {
		data := []byte(`{"jsonrpc":"2.0","id":"string-id","method":"test"}`)
		req, err := ParseJSONRPCRequest(data)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if req.ID != "string-id" {
			t.Errorf("Expected ID 'string-id', got %v", req.ID)
		}
	})

	t.Run("numeric ID", func(t *testing.T) {
		data := []byte(`{"jsonrpc":"2.0","id":123,"method":"test"}`)
		req, err := ParseJSONRPCRequest(data)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		// JSON numbers become float64
		if req.ID != float64(123) {
			t.Errorf("Expected ID 123, got %v", req.ID)
		}
	})

	t.Run("null ID (notification)", func(t *testing.T) {
		data := []byte(`{"jsonrpc":"2.0","method":"notification"}`)
		req, err := ParseJSONRPCRequest(data)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if req.ID != nil {
			t.Errorf("Expected nil ID, got %v", req.ID)
		}
	})
}

func TestJSONRPCRequest_Validate(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      float64(1),
			Method:  "tools/list",
		}
		err := req.Validate()
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("wrong version", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "1.0",
			ID:      float64(1),
			Method:  "test",
		}
		err := req.Validate()
		if err == nil {
			t.Error("Expected error for wrong version")
		}
		if err.Code != CodeInvalidRequest {
			t.Errorf("Expected code %d, got %d", CodeInvalidRequest, err.Code)
		}
	})

	t.Run("missing method", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      float64(1),
		}
		err := req.Validate()
		if err == nil {
			t.Error("Expected error for missing method")
		}
	})
}

func TestJSONRPCRequest_IsNotification(t *testing.T) {
	t.Run("with ID", func(t *testing.T) {
		req := &JSONRPCRequest{ID: float64(1)}
		if req.IsNotification() {
			t.Error("Request with ID should not be notification")
		}
	})

	t.Run("without ID", func(t *testing.T) {
		req := &JSONRPCRequest{}
		if !req.IsNotification() {
			t.Error("Request without ID should be notification")
		}
	})
}

func TestJSONRPCRequest_ParseInitializeParams(t *testing.T) {
	t.Run("with params", func(t *testing.T) {
		req := &JSONRPCRequest{
			Params: json.RawMessage(`{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"}}`),
		}
		params, err := req.ParseInitializeParams()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if params.ProtocolVersion != "2024-11-05" {
			t.Errorf("Expected protocol version '2024-11-05', got %s", params.ProtocolVersion)
		}
		if params.ClientInfo.Name != "test" {
			t.Errorf("Expected client name 'test', got %s", params.ClientInfo.Name)
		}
	})

	t.Run("without params", func(t *testing.T) {
		req := &JSONRPCRequest{}
		params, err := req.ParseInitializeParams()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if params == nil {
			t.Error("Expected empty params, got nil")
		}
	})

	t.Run("invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			Params: json.RawMessage(`{invalid`),
		}
		_, err := req.ParseInitializeParams()
		if err == nil {
			t.Error("Expected error for invalid params")
		}
	})
}

func TestJSONRPCRequest_ParseToolCallParams(t *testing.T) {
	t.Run("valid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			Params: json.RawMessage(`{"name":"my_tool","arguments":{"key":"value"}}`),
		}
		params, err := req.ParseToolCallParams()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if params.Name != "my_tool" {
			t.Errorf("Expected name 'my_tool', got %s", params.Name)
		}
		if params.Arguments["key"] != "value" {
			t.Errorf("Expected argument 'key' = 'value', got %v", params.Arguments["key"])
		}
	})

	t.Run("missing params", func(t *testing.T) {
		req := &JSONRPCRequest{}
		_, err := req.ParseToolCallParams()
		if err == nil {
			t.Error("Expected error for missing params")
		}
	})

	t.Run("missing name", func(t *testing.T) {
		req := &JSONRPCRequest{
			Params: json.RawMessage(`{"arguments":{}}`),
		}
		_, err := req.ParseToolCallParams()
		if err == nil {
			t.Error("Expected error for missing tool name")
		}
	})
}

func TestJSONRPCRequest_ParseReadResourceParams(t *testing.T) {
	t.Run("valid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			Params: json.RawMessage(`{"uri":"resource://test"}`),
		}
		params, err := req.ParseReadResourceParams()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if params.URI != "resource://test" {
			t.Errorf("Expected URI 'resource://test', got %s", params.URI)
		}
	})

	t.Run("missing params", func(t *testing.T) {
		req := &JSONRPCRequest{}
		_, err := req.ParseReadResourceParams()
		if err == nil {
			t.Error("Expected error for missing params")
		}
	})

	t.Run("missing URI", func(t *testing.T) {
		req := &JSONRPCRequest{
			Params: json.RawMessage(`{}`),
		}
		_, err := req.ParseReadResourceParams()
		if err == nil {
			t.Error("Expected error for missing URI")
		}
	})
}

func TestJSONRPCRequest_ParsePaginationParams(t *testing.T) {
	t.Run("with cursor", func(t *testing.T) {
		req := &JSONRPCRequest{
			Params: json.RawMessage(`{"cursor":"abc123"}`),
		}
		cursor, err := req.ParsePaginationParams()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if cursor != "abc123" {
			t.Errorf("Expected cursor 'abc123', got %s", cursor)
		}
	})

	t.Run("without cursor", func(t *testing.T) {
		req := &JSONRPCRequest{}
		cursor, err := req.ParsePaginationParams()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if cursor != "" {
			t.Errorf("Expected empty cursor, got %s", cursor)
		}
	})

	t.Run("invalid params ignored", func(t *testing.T) {
		req := &JSONRPCRequest{
			Params: json.RawMessage(`{invalid`),
		}
		cursor, err := req.ParsePaginationParams()
		if err != nil {
			t.Errorf("Pagination should ignore invalid params: %v", err)
		}
		if cursor != "" {
			t.Errorf("Expected empty cursor, got %s", cursor)
		}
	})
}

func TestNewSuccessResponse(t *testing.T) {
	result := map[string]string{"key": "value"}
	resp := NewSuccessResponse(float64(1), result)

	if resp.JSONRPC != "2.0" {
		t.Errorf("Expected jsonrpc '2.0', got %s", resp.JSONRPC)
	}
	if resp.ID != float64(1) {
		t.Errorf("Expected ID 1, got %v", resp.ID)
	}
	if resp.Error != nil {
		t.Error("Success response should not have error")
	}
	if resp.Result == nil {
		t.Error("Success response should have result")
	}
}

func TestNewErrorResponse(t *testing.T) {
	err := &JSONRPCError{Code: CodeInvalidParams, Message: "test error"}
	resp := NewErrorResponse(float64(2), err)

	if resp.JSONRPC != "2.0" {
		t.Errorf("Expected jsonrpc '2.0', got %s", resp.JSONRPC)
	}
	if resp.ID != float64(2) {
		t.Errorf("Expected ID 2, got %v", resp.ID)
	}
	if resp.Result != nil {
		t.Error("Error response should not have result")
	}
	if resp.Error == nil {
		t.Error("Error response should have error")
	}
	if resp.Error.Code != CodeInvalidParams {
		t.Errorf("Expected code %d, got %d", CodeInvalidParams, resp.Error.Code)
	}
}

func TestNewToolResultResponse(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		resp := NewToolResultResponse(float64(1), "result content", false)

		if resp.Error != nil {
			t.Error("Should not have error")
		}

		result, ok := resp.Result.(*ToolResult)
		if !ok {
			t.Fatalf("Expected ToolResult, got %T", resp.Result)
		}

		if result.IsError {
			t.Error("Expected IsError = false")
		}
		if len(result.Content) != 1 {
			t.Fatalf("Expected 1 content, got %d", len(result.Content))
		}
		if result.Content[0].Text != "result content" {
			t.Errorf("Expected text 'result content', got %s", result.Content[0].Text)
		}
	})

	t.Run("error", func(t *testing.T) {
		resp := NewToolResultResponse(float64(2), "error message", true)

		result, ok := resp.Result.(*ToolResult)
		if !ok {
			t.Fatalf("Expected ToolResult, got %T", resp.Result)
		}

		if !result.IsError {
			t.Error("Expected IsError = true")
		}
	})
}

func TestJSONRPCResponse_Bytes(t *testing.T) {
	resp := NewSuccessResponse(float64(1), "test")
	bytes, err := resp.Bytes()
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var parsed JSONRPCResponse
	if err := json.Unmarshal(bytes, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if parsed.JSONRPC != "2.0" {
		t.Errorf("Expected jsonrpc '2.0', got %s", parsed.JSONRPC)
	}
}
