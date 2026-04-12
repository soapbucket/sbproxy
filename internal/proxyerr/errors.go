// Package errors defines structured error types with HTTP status codes and machine-readable error codes.
package proxyerr

import (
	"errors"
	"fmt"
)

// Error Code Categories
type ErrorCode string

const (
	// Configuration errors (1xxx)
	// ErrCodeConfigLoad indicates a failure to load configuration from storage or file.
	ErrCodeConfigLoad ErrorCode = "CONFIG_1001"
	// ErrCodeConfigParse indicates a failure to parse configuration syntax (JSON/YAML).
	ErrCodeConfigParse ErrorCode = "CONFIG_1002"
	// ErrCodeConfigValidation indicates the configuration failed semantic validation.
	ErrCodeConfigValidation ErrorCode = "CONFIG_1003"
	// ErrCodeConfigNotFound indicates the requested configuration does not exist.
	ErrCodeConfigNotFound ErrorCode = "CONFIG_1004"
	// ErrCodeConfigInvalid indicates the configuration contains structurally invalid data.
	ErrCodeConfigInvalid ErrorCode = "CONFIG_1005"

	// Authentication errors (2xxx)

	// ErrCodeAuthFailed indicates an authentication attempt was rejected.
	ErrCodeAuthFailed ErrorCode = "AUTH_2001"
	// ErrCodeAuthExpired indicates the authentication token or session has expired.
	ErrCodeAuthExpired ErrorCode = "AUTH_2002"
	// ErrCodeAuthInvalid indicates the supplied credentials are malformed or unrecognized.
	ErrCodeAuthInvalid ErrorCode = "AUTH_2003"
	// ErrCodeAuthMissing indicates no authentication credentials were provided.
	ErrCodeAuthMissing ErrorCode = "AUTH_2004"
	// ErrCodeAuthUnauthorized indicates the caller lacks permission for the requested resource.
	ErrCodeAuthUnauthorized ErrorCode = "AUTH_2005"

	// Transport errors (3xxx)

	// ErrCodeTransportFailed indicates a generic failure communicating with the upstream.
	ErrCodeTransportFailed ErrorCode = "TRANSPORT_3001"
	// ErrCodeTransportTimeout indicates the upstream did not respond within the deadline.
	ErrCodeTransportTimeout ErrorCode = "TRANSPORT_3002"
	// ErrCodeTransportRetry indicates all retry attempts to the upstream have been exhausted.
	ErrCodeTransportRetry ErrorCode = "TRANSPORT_3003"
	// ErrCodeTransportCircuit indicates the circuit breaker is open and requests are being shed.
	ErrCodeTransportCircuit ErrorCode = "TRANSPORT_3004"

	// Cache errors (4xxx)

	// ErrCodeCacheMiss indicates the requested key was not found in the cache.
	ErrCodeCacheMiss ErrorCode = "CACHE_4001"
	// ErrCodeCacheWrite indicates a failure to write an entry to the cache.
	ErrCodeCacheWrite ErrorCode = "CACHE_4002"
	// ErrCodeCacheRead indicates a failure to read an entry from the cache.
	ErrCodeCacheRead ErrorCode = "CACHE_4003"
	// ErrCodeCacheExpired indicates the cached entry exists but has expired.
	ErrCodeCacheExpired ErrorCode = "CACHE_4004"

	// Request errors (5xxx)

	// ErrCodeBadRequest indicates the client sent a malformed or invalid request.
	ErrCodeBadRequest ErrorCode = "REQUEST_5001"
	// ErrCodeNotFound indicates the requested resource does not exist.
	ErrCodeNotFound ErrorCode = "REQUEST_5002"
	// ErrCodeMethodNotAllowed indicates the HTTP method is not supported for this endpoint.
	ErrCodeMethodNotAllowed ErrorCode = "REQUEST_5003"
	// ErrCodeRateLimited indicates the caller has exceeded the configured rate limit.
	ErrCodeRateLimited ErrorCode = "REQUEST_5004"

	// Internal errors (9xxx)

	// ErrCodeInternal indicates an unexpected internal server error.
	ErrCodeInternal ErrorCode = "INTERNAL_9001"
	// ErrCodeNotImplemented indicates the requested functionality is not yet implemented.
	ErrCodeNotImplemented ErrorCode = "INTERNAL_9002"
)

// ProxyError provides structured error information
type ProxyError struct {
	Code      ErrorCode
	Message   string
	Cause     error
	Details   map[string]interface{}
	Retryable bool
}

// Error implements the error interface
func (e *ProxyError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap returns the underlying error
func (e *ProxyError) Unwrap() error {
	return e.Cause
}

// WithDetail adds a detail to the error
func (e *ProxyError) WithDetail(key string, value interface{}) *ProxyError {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	e.Details[key] = value
	return e
}

// WithRetryable marks the error as retryable
func (e *ProxyError) WithRetryable(retryable bool) *ProxyError {
	e.Retryable = retryable
	return e
}

// New creates a new ProxyError
func New(code ErrorCode, message string) *ProxyError {
	return &ProxyError{
		Code:    code,
		Message: message,
	}
}

// Wrap wraps an error with a ProxyError
func Wrap(code ErrorCode, message string, cause error) *ProxyError {
	return &ProxyError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// Wrapf wraps an error with a formatted message
func Wrapf(code ErrorCode, cause error, format string, args ...interface{}) *ProxyError {
	return &ProxyError{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
		Cause:   cause,
	}
}

// Is checks if an error matches a specific error code
func Is(err error, code ErrorCode) bool {
	var proxyErr *ProxyError
	if errors.As(err, &proxyErr) {
		return proxyErr.Code == code
	}
	return false
}

// IsRetryable checks if an error can be retried
func IsRetryable(err error) bool {
	var proxyErr *ProxyError
	if errors.As(err, &proxyErr) {
		return proxyErr.Retryable
	}
	return false
}

// GetCode extracts the error code from an error
func GetCode(err error) ErrorCode {
	var proxyErr *ProxyError
	if errors.As(err, &proxyErr) {
		return proxyErr.Code
	}
	return ""
}

// GetDetails extracts error details
func GetDetails(err error) map[string]interface{} {
	var proxyErr *ProxyError
	if errors.As(err, &proxyErr) {
		return proxyErr.Details
	}
	return nil
}
