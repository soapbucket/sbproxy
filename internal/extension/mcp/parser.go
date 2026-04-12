// Package mcp implements the Model Context Protocol (MCP) for AI tool and resource integration.
package mcp

import (
	"encoding/json"
	"fmt"
)

// =============================================================================
// JSON-RPC Request Parsing
// =============================================================================

// ParseJSONRPCRequest parses a JSON-RPC 2.0 request from bytes.
func ParseJSONRPCRequest(data []byte) (*JSONRPCRequest, *MCPError) {
	if len(data) == 0 {
		return nil, NewParseError("empty request body")
	}

	var req JSONRPCRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, NewParseError(fmt.Sprintf("invalid JSON: %v", err))
	}

	return &req, nil
}

// Validate validates the JSON-RPC request structure.
func (r *JSONRPCRequest) Validate() *MCPError {
	// Check jsonrpc version
	if r.JSONRPC != "2.0" {
		return NewInvalidRequestError(fmt.Sprintf("invalid jsonrpc version: expected '2.0', got '%s'", r.JSONRPC))
	}

	// Check method is present
	if r.Method == "" {
		return NewInvalidRequestError("method is required")
	}

	return nil
}

// GetID returns the request ID, handling various types.
func (r *JSONRPCRequest) GetID() interface{} {
	return r.ID
}

// IsNotification returns true if this is a notification (no ID).
func (r *JSONRPCRequest) IsNotification() bool {
	return r.ID == nil
}

// =============================================================================
// Parameter Parsing
// =============================================================================

// ParseInitializeParams parses the params for an initialize request.
func (r *JSONRPCRequest) ParseInitializeParams() (*InitializeParams, *MCPError) {
	if r.Params == nil {
		return &InitializeParams{}, nil
	}

	var params InitializeParams
	if err := json.Unmarshal(r.Params, &params); err != nil {
		return nil, NewProtocolError(CodeInvalidParams, "invalid initialize params", err.Error())
	}

	return &params, nil
}

// ParseToolCallParams parses the params for a tools/call request.
func (r *JSONRPCRequest) ParseToolCallParams() (*ToolCallParams, *MCPError) {
	if r.Params == nil {
		return nil, NewProtocolError(CodeInvalidParams, "params required for tools/call", nil)
	}

	var params ToolCallParams
	if err := json.Unmarshal(r.Params, &params); err != nil {
		return nil, NewProtocolError(CodeInvalidParams, "invalid tool call params", err.Error())
	}

	if params.Name == "" {
		return nil, NewProtocolError(CodeInvalidParams, "tool name is required", nil)
	}

	return &params, nil
}

// ParseReadResourceParams parses the params for a resources/read request.
func (r *JSONRPCRequest) ParseReadResourceParams() (*ReadResourceParams, *MCPError) {
	if r.Params == nil {
		return nil, NewProtocolError(CodeInvalidParams, "params required for resources/read", nil)
	}

	var params ReadResourceParams
	if err := json.Unmarshal(r.Params, &params); err != nil {
		return nil, NewProtocolError(CodeInvalidParams, "invalid read resource params", err.Error())
	}

	if params.URI == "" {
		return nil, NewProtocolError(CodeInvalidParams, "uri is required", nil)
	}

	return &params, nil
}

// ParseGetPromptParams parses the params for a prompts/get request.
func (r *JSONRPCRequest) ParseGetPromptParams() (*GetPromptParams, *MCPError) {
	if r.Params == nil {
		return nil, NewProtocolError(CodeInvalidParams, "params required for prompts/get", nil)
	}

	var params GetPromptParams
	if err := json.Unmarshal(r.Params, &params); err != nil {
		return nil, NewProtocolError(CodeInvalidParams, "invalid prompt params", err.Error())
	}

	if params.Name == "" {
		return nil, NewProtocolError(CodeInvalidParams, "prompt name is required", nil)
	}

	return &params, nil
}

// ParsePaginationParams extracts optional pagination params.
func (r *JSONRPCRequest) ParsePaginationParams() (cursor string, err *MCPError) {
	if r.Params == nil {
		return "", nil
	}

	var params struct {
		Cursor string `json:"cursor"`
	}
	if jsonErr := json.Unmarshal(r.Params, &params); jsonErr != nil {
		// Pagination params are optional, ignore parse errors
		return "", nil
	}

	return params.Cursor, nil
}

// =============================================================================
// Response Building
// =============================================================================

// NewSuccessResponse creates a successful JSON-RPC response.
func NewSuccessResponse(id interface{}, result interface{}) *JSONRPCResponse {
	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

// NewErrorResponse creates an error JSON-RPC response.
func NewErrorResponse(id interface{}, err *JSONRPCError) *JSONRPCResponse {
	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   err,
	}
}

// NewToolResultResponse creates a tool result response.
func NewToolResultResponse(id interface{}, content string, isError bool) *JSONRPCResponse {
	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: &ToolResult{
			Content: []Content{
				{Type: "text", Text: content},
			},
			IsError: isError,
		},
	}
}

// =============================================================================
// Response Serialization
// =============================================================================

// MarshalJSON marshals the response to JSON.
func (r *JSONRPCResponse) MarshalJSON() ([]byte, error) {
	// Use an alias to avoid infinite recursion
	type Alias JSONRPCResponse
	return json.Marshal((*Alias)(r))
}

// Bytes returns the response as JSON bytes.
func (r *JSONRPCResponse) Bytes() ([]byte, error) {
	return json.Marshal(r)
}
