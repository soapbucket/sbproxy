// Package errors defines structured error types with HTTP status codes and machine-readable error codes.
package proxyerr

// Request error constructors

// BadRequestError creates a bad request error
func BadRequestError(message string) *ProxyError {
	return New(ErrCodeBadRequest, message)
}

// NotFoundError creates a not found error
func NotFoundError(resource string) *ProxyError {
	return New(ErrCodeNotFound, "resource not found").
		WithDetail("resource", resource)
}

// MethodNotAllowedError creates a method not allowed error
func MethodNotAllowedError(method string, allowed []string) *ProxyError {
	return New(ErrCodeMethodNotAllowed, "HTTP method not allowed").
		WithDetail("method", method).
		WithDetail("allowed", allowed)
}

// RateLimitedError creates a rate limited error
func RateLimitedError(limit int, window string) *ProxyError {
	return New(ErrCodeRateLimited, "rate limit exceeded").
		WithDetail("limit", limit).
		WithDetail("window", window).
		WithRetryable(true)
}

