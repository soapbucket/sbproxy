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
	ErrCodeConfigLoad       ErrorCode = "CONFIG_1001"
	// ErrCodeConfigParse is a sentinel error for code config parse conditions.
	ErrCodeConfigParse      ErrorCode = "CONFIG_1002"
	// ErrCodeConfigValidation is a sentinel error for code config validation conditions.
	ErrCodeConfigValidation ErrorCode = "CONFIG_1003"
	// ErrCodeConfigNotFound is a sentinel error for code config not found conditions.
	ErrCodeConfigNotFound   ErrorCode = "CONFIG_1004"
	// ErrCodeConfigInvalid is a sentinel error for code config invalid conditions.
	ErrCodeConfigInvalid    ErrorCode = "CONFIG_1005"

	// Authentication errors (2xxx)
	ErrCodeAuthFailed       ErrorCode = "AUTH_2001"
	// ErrCodeAuthExpired is a sentinel error for code auth expired conditions.
	ErrCodeAuthExpired      ErrorCode = "AUTH_2002"
	// ErrCodeAuthInvalid is a sentinel error for code auth invalid conditions.
	ErrCodeAuthInvalid      ErrorCode = "AUTH_2003"
	// ErrCodeAuthMissing is a sentinel error for code auth missing conditions.
	ErrCodeAuthMissing      ErrorCode = "AUTH_2004"
	// ErrCodeAuthUnauthorized is a sentinel error for code auth unauthorized conditions.
	ErrCodeAuthUnauthorized ErrorCode = "AUTH_2005"

	// Transport errors (3xxx)
	ErrCodeTransportFailed  ErrorCode = "TRANSPORT_3001"
	// ErrCodeTransportTimeout is a sentinel error for code transport timeout conditions.
	ErrCodeTransportTimeout ErrorCode = "TRANSPORT_3002"
	// ErrCodeTransportRetry is a sentinel error for code transport retry conditions.
	ErrCodeTransportRetry   ErrorCode = "TRANSPORT_3003"
	// ErrCodeTransportCircuit is a sentinel error for code transport circuit conditions.
	ErrCodeTransportCircuit ErrorCode = "TRANSPORT_3004"

	// Cache errors (4xxx)
	ErrCodeCacheMiss   ErrorCode = "CACHE_4001"
	// ErrCodeCacheWrite is a sentinel error for code cache write conditions.
	ErrCodeCacheWrite  ErrorCode = "CACHE_4002"
	// ErrCodeCacheRead is a sentinel error for code cache read conditions.
	ErrCodeCacheRead   ErrorCode = "CACHE_4003"
	// ErrCodeCacheExpired is a sentinel error for code cache expired conditions.
	ErrCodeCacheExpired ErrorCode = "CACHE_4004"

	// Request errors (5xxx)
	ErrCodeBadRequest   ErrorCode = "REQUEST_5001"
	// ErrCodeNotFound is a sentinel error for code not found conditions.
	ErrCodeNotFound     ErrorCode = "REQUEST_5002"
	// ErrCodeMethodNotAllowed is a sentinel error for code method not allowed conditions.
	ErrCodeMethodNotAllowed ErrorCode = "REQUEST_5003"
	// ErrCodeRateLimited is a sentinel error for code rate limited conditions.
	ErrCodeRateLimited  ErrorCode = "REQUEST_5004"

	// Internal errors (9xxx)
	ErrCodeInternal     ErrorCode = "INTERNAL_9001"
	// ErrCodeNotImplemented is a sentinel error for code not implemented conditions.
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

