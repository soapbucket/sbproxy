package transport

import (
	"net/http"

	"github.com/soapbucket/sbproxy/internal/platform/circuitbreaker"
)

// CircuitBreakerTransport wraps a transport with circuit breaker logic.
// When the upstream fails repeatedly, the circuit opens and requests
// are rejected immediately with a 503 until the timeout elapses.
type CircuitBreakerTransport struct {
	base http.RoundTripper
	cb   *circuitbreaker.CircuitBreaker
}

// NewCircuitBreakerTransport wraps tr with a named circuit breaker from the default registry.
func NewCircuitBreakerTransport(tr http.RoundTripper, name string, cfg circuitbreaker.Config) http.RoundTripper {
	cfg.Name = name
	cb := circuitbreaker.DefaultRegistry.GetOrCreate(name, cfg)
	return &CircuitBreakerTransport{base: tr, cb: cb}
}

// RoundTrip executes the request through the circuit breaker.
func (t *CircuitBreakerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	err := t.cb.Call(func() error {
		var roundTripErr error
		resp, roundTripErr = t.base.RoundTrip(req)
		// Treat 502/503/504 as failures for the circuit breaker.
		if roundTripErr == nil && resp != nil && (resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504) {
			return &upstreamError{statusCode: resp.StatusCode}
		}
		return roundTripErr
	})

	if err == circuitbreaker.ErrCircuitOpen {
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Status:     "503 Service Unavailable",
			Header: http.Header{
				"Content-Type": {"text/plain; charset=utf-8"},
				"Retry-After":  {"5"},
			},
			Body:    http.NoBody,
			Request: req,
		}, nil
	}

	return resp, err
}

// upstreamError signals a server-side failure to the circuit breaker
// without losing the original response.
type upstreamError struct {
	statusCode int
}

func (e *upstreamError) Error() string {
	return "upstream returned server error"
}
