// Package errors defines structured error types with HTTP status codes and machine-readable error codes.
package proxyerr

import "time"

// Transport error constructors

// TransportError creates a generic transport error
func TransportError(cause error) *ProxyError {
	return Wrap(ErrCodeTransportFailed, "transport request failed", cause).
		WithRetryable(true)
}

// TransportTimeoutError creates a timeout error
func TransportTimeoutError(timeout time.Duration) *ProxyError {
	return New(ErrCodeTransportTimeout, "transport request timed out").
		WithDetail("timeout", timeout).
		WithRetryable(true)
}

// TransportRetryError creates a retry exhausted error
func TransportRetryError(attempts int) *ProxyError {
	return New(ErrCodeTransportRetry, "transport retry attempts exhausted").
		WithDetail("attempts", attempts).
		WithRetryable(false)
}

// TransportCircuitOpenError creates a circuit breaker open error
func TransportCircuitOpenError(target string) *ProxyError {
	return New(ErrCodeTransportCircuit, "circuit breaker is open").
		WithDetail("target", target).
		WithRetryable(false)
}

