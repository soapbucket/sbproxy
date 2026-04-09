// Package errors defines structured error types with HTTP status codes and machine-readable error codes.
package proxyerr

// Authentication error constructors

// AuthFailedError creates an authentication failed error
func AuthFailedError(reason string) *ProxyError {
	return New(ErrCodeAuthFailed, "authentication failed").
		WithDetail("reason", reason)
}

// AuthExpiredError creates an authentication expired error
func AuthExpiredError() *ProxyError {
	return New(ErrCodeAuthExpired, "authentication token expired")
}

// AuthInvalidError creates an invalid authentication error
func AuthInvalidError(message string) *ProxyError {
	return New(ErrCodeAuthInvalid, message)
}

// AuthMissingError creates a missing authentication error
func AuthMissingError() *ProxyError {
	return New(ErrCodeAuthMissing, "authentication credentials missing")
}

// AuthUnauthorizedError creates an unauthorized error
func AuthUnauthorizedError(resource string) *ProxyError {
	return New(ErrCodeAuthUnauthorized, "unauthorized access").
		WithDetail("resource", resource)
}

