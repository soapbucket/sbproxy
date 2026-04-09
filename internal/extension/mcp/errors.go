// Package mcp implements the Model Context Protocol (MCP) for AI tool and resource integration.
package mcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// =============================================================================
// JSON-RPC 2.0 Standard Error Codes
// =============================================================================

const (
	// Standard JSON-RPC 2.0 error codes
	CodeParseError     = -32700 // Invalid JSON was received
	// CodeInvalidRequest is a constant for code invalid request.
	CodeInvalidRequest = -32600 // The JSON sent is not a valid Request object
	// CodeMethodNotFound is a constant for code method not found.
	CodeMethodNotFound = -32601 // The method does not exist / is not available
	// CodeInvalidParams is a constant for code invalid params.
	CodeInvalidParams  = -32602 // Invalid method parameter(s)
	// CodeInternalError is a constant for code internal error.
	CodeInternalError  = -32603 // Internal JSON-RPC error

	// Server error codes (-32000 to -32099 reserved for implementation-defined server errors)
	CodeToolNotFound     = -32000 // Tool not found
	// CodeToolExecError is a constant for code tool exec error.
	CodeToolExecError    = -32001 // Tool execution error
	// CodeTimeoutError is a constant for code timeout error.
	CodeTimeoutError     = -32002 // Operation timed out
	// CodeUpstreamError is a constant for code upstream error.
	CodeUpstreamError    = -32003 // Upstream API error
	// CodeValidationError is a constant for code validation error.
	CodeValidationError  = -32004 // Validation error
	// CodeCircuitOpenError is a constant for code circuit open error.
	CodeCircuitOpenError = -32005 // Circuit breaker is open
)

// =============================================================================
// Pre-defined JSON-RPC Errors
// =============================================================================

var (
	// ErrParseError is a sentinel error for parse error conditions.
	ErrParseError = &JSONRPCError{
		Code:    CodeParseError,
		Message: "Parse error",
	}
	// ErrInvalidRequest is a sentinel error for invalid request conditions.
	ErrInvalidRequest = &JSONRPCError{
		Code:    CodeInvalidRequest,
		Message: "Invalid Request",
	}
	// ErrMethodNotFound is a sentinel error for method not found conditions.
	ErrMethodNotFound = &JSONRPCError{
		Code:    CodeMethodNotFound,
		Message: "Method not found",
	}
	// ErrInvalidParams is a sentinel error for invalid params conditions.
	ErrInvalidParams = &JSONRPCError{
		Code:    CodeInvalidParams,
		Message: "Invalid params",
	}
	// ErrInternalError is a sentinel error for internal error conditions.
	ErrInternalError = &JSONRPCError{
		Code:    CodeInternalError,
		Message: "Internal error",
	}
)

// =============================================================================
// MCP Error Type
// =============================================================================

// MCPErrorType categorizes MCP errors.
type MCPErrorType int

const (
	// Protocol errors (returned in JSON-RPC error field)
	ErrorTypeProtocol MCPErrorType = iota

	// Tool execution errors (returned in result with isError: true)
	ErrorTypeToolExecution
	// ErrorTypeTimeout is a sentinel error for or type timeout conditions.
	ErrorTypeTimeout
	// ErrorTypeUpstream is a sentinel error for or type upstream conditions.
	ErrorTypeUpstream
	// ErrorTypeValidation is a sentinel error for or type validation conditions.
	ErrorTypeValidation
	// ErrorTypeTransform is a sentinel error for or type transform conditions.
	ErrorTypeTransform
	// ErrorTypeCircuitOpen is a sentinel error for or type circuit open conditions.
	ErrorTypeCircuitOpen
)

// String returns a human-readable representation of the MCPErrorType.
func (t MCPErrorType) String() string {
	switch t {
	case ErrorTypeProtocol:
		return "protocol"
	case ErrorTypeToolExecution:
		return "tool_execution"
	case ErrorTypeTimeout:
		return "timeout"
	case ErrorTypeUpstream:
		return "upstream"
	case ErrorTypeValidation:
		return "validation"
	case ErrorTypeTransform:
		return "transform"
	case ErrorTypeCircuitOpen:
		return "circuit_open"
	default:
		return "unknown"
	}
}

// MCPError represents an error during MCP processing.
type MCPError struct {
	Type      MCPErrorType
	Code      int
	Message   string
	Details   interface{}
	Cause     error
	Retryable bool
	ToolName  string
	StepName  string
}

// Error performs the error operation on the MCPError.
func (e *MCPError) Error() string {
	var parts []string
	parts = append(parts, fmt.Sprintf("mcp %s", e.Type))
	if e.ToolName != "" {
		parts = append(parts, fmt.Sprintf("tool=%s", e.ToolName))
	}
	if e.StepName != "" {
		parts = append(parts, fmt.Sprintf("step=%s", e.StepName))
	}
	parts = append(parts, e.Message)
	if e.Cause != nil {
		parts = append(parts, fmt.Sprintf("cause=%v", e.Cause))
	}
	return strings.Join(parts, ": ")
}

// Unwrap performs the unwrap operation on the MCPError.
func (e *MCPError) Unwrap() error {
	return e.Cause
}

// IsProtocolError returns true if this is a protocol-level error.
func (e *MCPError) IsProtocolError() bool {
	return e.Type == ErrorTypeProtocol
}

// IsRetryable returns true if the operation might succeed on retry.
func (e *MCPError) IsRetryable() bool {
	return e.Retryable
}

// IsTimeout returns true if this error was caused by a timeout.
func (e *MCPError) IsTimeout() bool {
	if e.Type == ErrorTypeTimeout {
		return true
	}
	if e.Cause != nil {
		if errors.Is(e.Cause, context.DeadlineExceeded) {
			return true
		}
		if strings.Contains(e.Cause.Error(), "context deadline exceeded") {
			return true
		}
	}
	return false
}

// ToJSONRPCError converts this error to a JSON-RPC error response.
func (e *MCPError) ToJSONRPCError() *JSONRPCError {
	return &JSONRPCError{
		Code:    e.Code,
		Message: e.Message,
		Data:    e.Details,
	}
}

// ToToolResult converts this error to a tool result with isError: true.
func (e *MCPError) ToToolResult() *ToolResult {
	return &ToolResult{
		Content: []Content{
			{Type: "text", Text: e.Message},
		},
		IsError: true,
	}
}

// =============================================================================
// Error Constructors
// =============================================================================

// NewProtocolError creates a new protocol-level error.
func NewProtocolError(code int, message string, details interface{}) *MCPError {
	return &MCPError{
		Type:    ErrorTypeProtocol,
		Code:    code,
		Message: message,
		Details: details,
	}
}

// NewParseError creates a parse error.
func NewParseError(details interface{}) *MCPError {
	return &MCPError{
		Type:    ErrorTypeProtocol,
		Code:    CodeParseError,
		Message: "Parse error: invalid JSON",
		Details: details,
	}
}

// NewInvalidRequestError creates an invalid request error.
func NewInvalidRequestError(details interface{}) *MCPError {
	return &MCPError{
		Type:    ErrorTypeProtocol,
		Code:    CodeInvalidRequest,
		Message: "Invalid Request",
		Details: details,
	}
}

// NewMethodNotFoundError creates a method not found error.
func NewMethodNotFoundError(method string) *MCPError {
	return &MCPError{
		Type:    ErrorTypeProtocol,
		Code:    CodeMethodNotFound,
		Message: fmt.Sprintf("Method not found: %s", method),
		Details: map[string]string{"method": method},
	}
}

// NewToolNotFoundError creates a tool not found error.
func NewToolNotFoundError(toolName string) *MCPError {
	return &MCPError{
		Type:    ErrorTypeProtocol,
		Code:    CodeToolNotFound,
		Message: fmt.Sprintf("Unknown tool: %s", toolName),
		Details: map[string]string{"tool": toolName},
	}
}

// NewValidationError creates a validation error with details.
func NewValidationError(toolName string, validationErrors []string) *MCPError {
	return &MCPError{
		Type:    ErrorTypeProtocol,
		Code:    CodeInvalidParams,
		Message: "Invalid params: validation failed",
		Details: map[string]interface{}{
			"tool":              toolName,
			"validation_errors": validationErrors,
		},
	}
}

// NewToolExecutionError creates a tool execution error.
func NewToolExecutionError(toolName string, message string, cause error) *MCPError {
	return &MCPError{
		Type:     ErrorTypeToolExecution,
		Code:     CodeToolExecError,
		Message:  message,
		Cause:    cause,
		ToolName: toolName,
	}
}

// NewTimeoutError creates a timeout error.
func NewTimeoutError(toolName string, stepName string) *MCPError {
	msg := fmt.Sprintf("Tool '%s' execution timed out", toolName)
	if stepName != "" {
		msg = fmt.Sprintf("Tool '%s' timed out at step '%s'", toolName, stepName)
	}
	return &MCPError{
		Type:      ErrorTypeTimeout,
		Code:      CodeTimeoutError,
		Message:   msg,
		Retryable: true,
		ToolName:  toolName,
		StepName:  stepName,
	}
}

// NewUpstreamError creates an upstream API error.
func NewUpstreamError(toolName string, stepName string, statusCode int, body string, cause error) *MCPError {
	msg := fmt.Sprintf("Upstream API error: HTTP %d", statusCode)
	if stepName != "" {
		msg = fmt.Sprintf("Upstream API error at step '%s': HTTP %d", stepName, statusCode)
	}

	retryable := statusCode >= 500 || statusCode == 429

	return &MCPError{
		Type:      ErrorTypeUpstream,
		Code:      CodeUpstreamError,
		Message:   msg,
		Cause:     cause,
		Retryable: retryable,
		ToolName:  toolName,
		StepName:  stepName,
		Details: map[string]interface{}{
			"status_code": statusCode,
			"body":        truncateString(body, 500),
		},
	}
}

// NewTransformError creates a transform error.
func NewTransformError(toolName string, message string, cause error) *MCPError {
	return &MCPError{
		Type:     ErrorTypeTransform,
		Code:     CodeToolExecError,
		Message:  fmt.Sprintf("Transform error: %s", message),
		Cause:    cause,
		ToolName: toolName,
	}
}

// NewCircuitOpenError creates a circuit breaker open error.
func NewCircuitOpenError(toolName string) *MCPError {
	return &MCPError{
		Type:      ErrorTypeCircuitOpen,
		Code:      CodeCircuitOpenError,
		Message:   "Service temporarily unavailable. Please try again later.",
		Retryable: true,
		ToolName:  toolName,
	}
}

// NewInternalError creates an internal error.
func NewInternalError(message string, cause error) *MCPError {
	return &MCPError{
		Type:    ErrorTypeProtocol,
		Code:    CodeInternalError,
		Message: message,
		Cause:   cause,
	}
}

// =============================================================================
// Error Handler
// =============================================================================

// ErrorHandler processes errors and builds appropriate responses.
type ErrorHandler struct {
	config *ErrorHandlingConfig
	logger *slog.Logger
}

// NewErrorHandler creates a new error handler.
func NewErrorHandler(config *ErrorHandlingConfig) *ErrorHandler {
	if config == nil {
		config = &ErrorHandlingConfig{}
	}
	return &ErrorHandler{
		config: config,
		logger: slog.Default(),
	}
}

// HandleError processes an error and returns the appropriate JSON-RPC response.
func (h *ErrorHandler) HandleError(requestID interface{}, err *MCPError) *JSONRPCResponse {
	// Log the error
	h.logger.Error("mcp error",
		"type", err.Type.String(),
		"code", err.Code,
		"message", err.Message,
		"tool", err.ToolName,
		"step", err.StepName,
		"retryable", err.Retryable,
		"cause", err.Cause,
	)

	// Build response based on error type
	if err.IsProtocolError() {
		// Protocol errors go in the error field
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      requestID,
			Error:   err.ToJSONRPCError(),
		}
	}

	// Tool execution errors go in the result with isError: true
	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      requestID,
		Result:  err.ToToolResult(),
	}
}

// WrapError wraps a generic error as an MCPError.
func (h *ErrorHandler) WrapError(err error, toolName string) *MCPError {
	// Check if already an MCPError
	var mcpErr *MCPError
	if errors.As(err, &mcpErr) {
		return mcpErr
	}

	// Check for mapped tool errors (from error_mapping) - these should return
	// as tool results with isError: true, not as JSON-RPC protocol errors
	var mapped *mappedToolError
	if errors.As(err, &mapped) {
		return &MCPError{
			Type:     ErrorTypeToolExecution,
			Code:     CodeToolExecError,
			Message:  mapped.message,
			ToolName: toolName,
		}
	}

	// Check for context deadline exceeded
	if errors.Is(err, context.DeadlineExceeded) {
		return NewTimeoutError(toolName, "")
	}

	// Generic tool execution error
	return NewToolExecutionError(toolName, err.Error(), err)
}

// =============================================================================
// Helper Functions
// =============================================================================

// truncateString truncates a string to the specified length.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// WithData returns a copy of the JSON-RPC error with additional data.
func (e *JSONRPCError) WithData(data interface{}) *JSONRPCError {
	return &JSONRPCError{
		Code:    e.Code,
		Message: e.Message,
		Data:    data,
	}
}

// WithMessage returns a copy of the JSON-RPC error with a custom message.
func (e *JSONRPCError) WithMessage(message string) *JSONRPCError {
	return &JSONRPCError{
		Code:    e.Code,
		Message: message,
		Data:    e.Data,
	}
}
