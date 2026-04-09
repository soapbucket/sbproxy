// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	json "github.com/goccy/go-json"
	"fmt"
	"net/http"
)

// AIError represents an OpenAI-compatible error response.
type AIError struct {
	StatusCode int    `json:"-"`
	Type       string `json:"type"`
	Message    string `json:"message"`
	Param      string `json:"param,omitempty"`
	Code       string `json:"code,omitempty"`
}

// Error performs the error operation on the AIError.
func (e *AIError) Error() string {
	return fmt.Sprintf("ai error [%d] %s: %s", e.StatusCode, e.Type, e.Message)
}

// ErrorResponse is the wire format for error responses.
type ErrorResponse struct {
	Error AIError `json:"error"`
}

// WriteError writes an OpenAI-compatible error response.
func WriteError(w http.ResponseWriter, err *AIError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.StatusCode)
	json.NewEncoder(w).Encode(ErrorResponse{Error: *err})
}

// Common error constructors

// ErrInvalidRequest performs the err invalid request operation.
func ErrInvalidRequest(msg string) *AIError {
	return &AIError{
		StatusCode: http.StatusBadRequest,
		Type:       "invalid_request_error",
		Message:    msg,
	}
}

// ErrContextLengthExceeded returns a 400 error when input exceeds the model's context window.
func ErrContextLengthExceeded(msg string) *AIError {
	return &AIError{
		StatusCode: http.StatusBadRequest,
		Type:       "invalid_request_error",
		Message:    msg,
		Code:       "context_length_exceeded",
	}
}

// ErrModelNotFound performs the err model not found operation.
func ErrModelNotFound(model string) *AIError {
	return &AIError{
		StatusCode: http.StatusNotFound,
		Type:       "invalid_request_error",
		Message:    fmt.Sprintf("The model '%s' does not exist or you do not have access to it.", model),
		Code:       "model_not_found",
	}
}

// ErrProviderUnavailable performs the err provider unavailable operation.
func ErrProviderUnavailable(provider string) *AIError {
	return &AIError{
		StatusCode: http.StatusBadGateway,
		Type:       "server_error",
		Message:    fmt.Sprintf("Provider '%s' is currently unavailable.", provider),
	}
}

// ErrAllProvidersUnavailable performs the err all providers unavailable operation.
func ErrAllProvidersUnavailable() *AIError {
	return &AIError{
		StatusCode: http.StatusBadGateway,
		Type:       "server_error",
		Message:    "All configured providers are currently unavailable.",
	}
}

// ErrRateLimited performs the err rate limited operation.
func ErrRateLimited(msg string) *AIError {
	return &AIError{
		StatusCode: http.StatusTooManyRequests,
		Type:       "rate_limit_error",
		Message:    msg,
	}
}

// ErrBudgetExceeded performs the err budget exceeded operation.
func ErrBudgetExceeded(msg string) *AIError {
	return &AIError{
		StatusCode: http.StatusTooManyRequests,
		Type:       "budget_exceeded",
		Message:    msg,
		Code:       "budget_exceeded",
	}
}

// ErrGuardrailBlocked performs the err guardrail blocked operation.
func ErrGuardrailBlocked(guardrail, reason string) *AIError {
	return &AIError{
		StatusCode: http.StatusBadRequest,
		Type:       "guardrail_blocked",
		Message:    fmt.Sprintf("Request blocked by guardrail '%s': %s", guardrail, reason),
		Code:       "guardrail_blocked",
	}
}

// ErrInternal performs the err internal operation.
func ErrInternal(msg string) *AIError {
	return &AIError{
		StatusCode: http.StatusInternalServerError,
		Type:       "server_error",
		Message:    msg,
	}
}

// ErrMethodNotAllowed performs the err method not allowed operation.
func ErrMethodNotAllowed() *AIError {
	return &AIError{
		StatusCode: http.StatusMethodNotAllowed,
		Type:       "invalid_request_error",
		Message:    "Method not allowed.",
	}
}

// ErrNotFound performs the err not found operation.
func ErrNotFound() *AIError {
	return &AIError{
		StatusCode: http.StatusNotFound,
		Type:       "invalid_request_error",
		Message:    "Not found.",
	}
}

// ErrServiceUnavailable returns a 503 error when all providers are down and no degraded response is available.
func ErrServiceUnavailable() *AIError {
	return &AIError{
		StatusCode: http.StatusServiceUnavailable,
		Type:       "server_error",
		Message:    "All configured providers are currently unavailable. No cached or fallback response is available.",
		Code:       "service_unavailable",
	}
}

// IsRetryable returns true if the error status code should trigger a retry.
func IsRetryable(statusCode int) bool {
	switch statusCode {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}
