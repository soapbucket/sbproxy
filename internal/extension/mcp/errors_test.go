package mcp

import (
	"context"
	"errors"
	"testing"
)

func TestMCPError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *MCPError
		contains []string
	}{
		{
			name: "basic error",
			err: &MCPError{
				Type:    ErrorTypeToolExecution,
				Message: "tool failed",
			},
			contains: []string{"mcp", "tool_execution", "tool failed"},
		},
		{
			name: "error with tool name",
			err: &MCPError{
				Type:     ErrorTypeToolExecution,
				Message:  "execution failed",
				ToolName: "get_weather",
			},
			contains: []string{"tool=get_weather", "execution failed"},
		},
		{
			name: "error with step name",
			err: &MCPError{
				Type:     ErrorTypeUpstream,
				Message:  "upstream error",
				ToolName: "get_weather",
				StepName: "fetch_data",
			},
			contains: []string{"tool=get_weather", "step=fetch_data"},
		},
		{
			name: "error with cause",
			err: &MCPError{
				Type:    ErrorTypeToolExecution,
				Message: "failed",
				Cause:   errors.New("underlying error"),
			},
			contains: []string{"failed", "underlying error"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			for _, substr := range tt.contains {
				if !containsString(errStr, substr) {
					t.Errorf("Error string %q should contain %q", errStr, substr)
				}
			}
		})
	}
}

func TestMCPError_IsTimeout(t *testing.T) {
	tests := []struct {
		name      string
		err       *MCPError
		isTimeout bool
	}{
		{
			name: "timeout type",
			err: &MCPError{
				Type:    ErrorTypeTimeout,
				Message: "timed out",
			},
			isTimeout: true,
		},
		{
			name: "context deadline exceeded cause",
			err: &MCPError{
				Type:  ErrorTypeToolExecution,
				Cause: context.DeadlineExceeded,
			},
			isTimeout: true,
		},
		{
			name: "deadline exceeded in message",
			err: &MCPError{
				Type:  ErrorTypeToolExecution,
				Cause: errors.New("context deadline exceeded"),
			},
			isTimeout: true,
		},
		{
			name: "not a timeout",
			err: &MCPError{
				Type:    ErrorTypeToolExecution,
				Message: "some other error",
			},
			isTimeout: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.IsTimeout() != tt.isTimeout {
				t.Errorf("Expected IsTimeout() = %v, got %v", tt.isTimeout, tt.err.IsTimeout())
			}
		})
	}
}

func TestMCPError_IsRetryable(t *testing.T) {
	tests := []struct {
		name        string
		err         *MCPError
		isRetryable bool
	}{
		{
			name: "retryable flag set",
			err: &MCPError{
				Type:      ErrorTypeTimeout,
				Retryable: true,
			},
			isRetryable: true,
		},
		{
			name: "not retryable",
			err: &MCPError{
				Type:      ErrorTypeValidation,
				Retryable: false,
			},
			isRetryable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.IsRetryable() != tt.isRetryable {
				t.Errorf("Expected IsRetryable() = %v, got %v", tt.isRetryable, tt.err.IsRetryable())
			}
		})
	}
}

func TestMCPError_IsProtocolError(t *testing.T) {
	protocolErr := &MCPError{Type: ErrorTypeProtocol}
	if !protocolErr.IsProtocolError() {
		t.Error("Expected IsProtocolError() = true for ErrorTypeProtocol")
	}

	toolErr := &MCPError{Type: ErrorTypeToolExecution}
	if toolErr.IsProtocolError() {
		t.Error("Expected IsProtocolError() = false for ErrorTypeToolExecution")
	}
}

func TestMCPError_ToJSONRPCError(t *testing.T) {
	err := &MCPError{
		Type:    ErrorTypeProtocol,
		Code:    CodeInvalidParams,
		Message: "invalid params",
		Details: map[string]string{"field": "value"},
	}

	jsonRPCErr := err.ToJSONRPCError()

	if jsonRPCErr.Code != CodeInvalidParams {
		t.Errorf("Expected code %d, got %d", CodeInvalidParams, jsonRPCErr.Code)
	}

	if jsonRPCErr.Message != "invalid params" {
		t.Errorf("Expected message 'invalid params', got %s", jsonRPCErr.Message)
	}

	if jsonRPCErr.Data == nil {
		t.Error("Expected data to be set")
	}
}

func TestMCPError_ToToolResult(t *testing.T) {
	err := &MCPError{
		Type:    ErrorTypeToolExecution,
		Message: "tool failed",
	}

	result := err.ToToolResult()

	if !result.IsError {
		t.Error("Expected IsError = true")
	}

	if len(result.Content) != 1 {
		t.Fatalf("Expected 1 content item, got %d", len(result.Content))
	}

	if result.Content[0].Type != "text" {
		t.Errorf("Expected content type 'text', got %s", result.Content[0].Type)
	}

	if result.Content[0].Text != "tool failed" {
		t.Errorf("Expected text 'tool failed', got %s", result.Content[0].Text)
	}
}

func TestMCPErrorType_String(t *testing.T) {
	tests := []struct {
		errType  MCPErrorType
		expected string
	}{
		{ErrorTypeProtocol, "protocol"},
		{ErrorTypeToolExecution, "tool_execution"},
		{ErrorTypeTimeout, "timeout"},
		{ErrorTypeUpstream, "upstream"},
		{ErrorTypeValidation, "validation"},
		{ErrorTypeTransform, "transform"},
		{ErrorTypeCircuitOpen, "circuit_open"},
		{MCPErrorType(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.errType.String() != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, tt.errType.String())
			}
		})
	}
}

func TestErrorConstructors(t *testing.T) {
	t.Run("NewParseError", func(t *testing.T) {
		err := NewParseError("bad json")
		if err.Type != ErrorTypeProtocol {
			t.Error("Expected ErrorTypeProtocol")
		}
		if err.Code != CodeParseError {
			t.Errorf("Expected code %d, got %d", CodeParseError, err.Code)
		}
	})

	t.Run("NewInvalidRequestError", func(t *testing.T) {
		err := NewInvalidRequestError("missing field")
		if err.Code != CodeInvalidRequest {
			t.Errorf("Expected code %d, got %d", CodeInvalidRequest, err.Code)
		}
	})

	t.Run("NewMethodNotFoundError", func(t *testing.T) {
		err := NewMethodNotFoundError("unknown/method")
		if err.Code != CodeMethodNotFound {
			t.Errorf("Expected code %d, got %d", CodeMethodNotFound, err.Code)
		}
		if !containsString(err.Message, "unknown/method") {
			t.Error("Expected message to contain method name")
		}
	})

	t.Run("NewToolNotFoundError", func(t *testing.T) {
		err := NewToolNotFoundError("missing_tool")
		if err.Code != CodeToolNotFound {
			t.Errorf("Expected code %d, got %d", CodeToolNotFound, err.Code)
		}
		if !containsString(err.Message, "missing_tool") {
			t.Error("Expected message to contain tool name")
		}
	})

	t.Run("NewValidationError", func(t *testing.T) {
		err := NewValidationError("my_tool", []string{"field1: required", "field2: invalid"})
		if err.Code != CodeInvalidParams {
			t.Errorf("Expected code %d, got %d", CodeInvalidParams, err.Code)
		}
		if err.Details == nil {
			t.Error("Expected details to be set")
		}
	})

	t.Run("NewTimeoutError", func(t *testing.T) {
		err := NewTimeoutError("slow_tool", "step1")
		if err.Type != ErrorTypeTimeout {
			t.Error("Expected ErrorTypeTimeout")
		}
		if !err.Retryable {
			t.Error("Timeout errors should be retryable")
		}
		if err.ToolName != "slow_tool" {
			t.Error("Expected tool name to be set")
		}
		if err.StepName != "step1" {
			t.Error("Expected step name to be set")
		}
	})

	t.Run("NewUpstreamError_5xx", func(t *testing.T) {
		err := NewUpstreamError("api_tool", "fetch", 503, "Service Unavailable", nil)
		if err.Type != ErrorTypeUpstream {
			t.Error("Expected ErrorTypeUpstream")
		}
		if !err.Retryable {
			t.Error("5xx errors should be retryable")
		}
	})

	t.Run("NewUpstreamError_4xx", func(t *testing.T) {
		err := NewUpstreamError("api_tool", "fetch", 400, "Bad Request", nil)
		if err.Retryable {
			t.Error("4xx errors should not be retryable")
		}
	})

	t.Run("NewCircuitOpenError", func(t *testing.T) {
		err := NewCircuitOpenError("failing_tool")
		if err.Type != ErrorTypeCircuitOpen {
			t.Error("Expected ErrorTypeCircuitOpen")
		}
		if !err.Retryable {
			t.Error("Circuit open errors should be retryable")
		}
	})
}

func TestErrorHandler_HandleError(t *testing.T) {
	handler := NewErrorHandler(nil)

	t.Run("protocol error", func(t *testing.T) {
		err := NewMethodNotFoundError("bad/method")
		resp := handler.HandleError(float64(1), err)

		if resp.Error == nil {
			t.Fatal("Expected error in response")
		}
		if resp.Error.Code != CodeMethodNotFound {
			t.Errorf("Expected code %d, got %d", CodeMethodNotFound, resp.Error.Code)
		}
		if resp.Result != nil {
			t.Error("Protocol errors should not have result")
		}
	})

	t.Run("tool execution error", func(t *testing.T) {
		err := NewToolExecutionError("my_tool", "execution failed", nil)
		resp := handler.HandleError(float64(2), err)

		if resp.Error != nil {
			t.Error("Tool errors should not be in error field")
		}
		if resp.Result == nil {
			t.Fatal("Expected result in response")
		}
		result, ok := resp.Result.(*ToolResult)
		if !ok {
			t.Fatalf("Expected ToolResult, got %T", resp.Result)
		}
		if !result.IsError {
			t.Error("Expected IsError = true")
		}
	})
}

func TestErrorHandler_WrapError(t *testing.T) {
	handler := NewErrorHandler(nil)

	t.Run("already MCPError", func(t *testing.T) {
		original := NewTimeoutError("tool", "step")
		wrapped := handler.WrapError(original, "tool")

		if wrapped != original {
			t.Error("Should return original MCPError unchanged")
		}
	})

	t.Run("context deadline exceeded", func(t *testing.T) {
		wrapped := handler.WrapError(context.DeadlineExceeded, "slow_tool")
		if wrapped.Type != ErrorTypeTimeout {
			t.Errorf("Expected ErrorTypeTimeout, got %v", wrapped.Type)
		}
	})

	t.Run("generic error", func(t *testing.T) {
		wrapped := handler.WrapError(errors.New("something failed"), "some_tool")
		if wrapped.Type != ErrorTypeToolExecution {
			t.Errorf("Expected ErrorTypeToolExecution, got %v", wrapped.Type)
		}
		if wrapped.ToolName != "some_tool" {
			t.Errorf("Expected tool name 'some_tool', got %s", wrapped.ToolName)
		}
	})
}

func TestJSONRPCError_WithData(t *testing.T) {
	original := ErrInvalidParams
	withData := original.WithData(map[string]string{"field": "invalid"})

	if withData.Code != original.Code {
		t.Error("Code should be preserved")
	}
	if withData.Message != original.Message {
		t.Error("Message should be preserved")
	}
	if withData.Data == nil {
		t.Error("Data should be set")
	}
}

func TestJSONRPCError_WithMessage(t *testing.T) {
	original := ErrInternalError
	withMessage := original.WithMessage("custom message")

	if withMessage.Code != original.Code {
		t.Error("Code should be preserved")
	}
	if withMessage.Message != "custom message" {
		t.Errorf("Expected 'custom message', got %s", withMessage.Message)
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is a longer string", 10, "this is a ..."},
		{"", 5, ""},
	}

	for _, tt := range tests {
		result := truncateString(tt.input, tt.maxLen)
		if result != tt.expected {
			t.Errorf("truncateString(%q, %d) = %q, expected %q", tt.input, tt.maxLen, result, tt.expected)
		}
	}
}

// Helper
func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
