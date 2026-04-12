// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"log/slog"
	"net/http"
	"time"
)

// DelayTransport adds a configurable delay before making requests
// Useful for rate limiting, testing, or protecting slow origins
type DelayTransport struct {
	// Base transport to wrap
	Base http.RoundTripper

	// Delay to wait before each request
	Delay time.Duration

	// Optional: Delay only on specific conditions
	DelayFunc func(*http.Request) time.Duration
}

// NewDelayTransport creates a new delay transport
func NewDelayTransport(base http.RoundTripper, delay time.Duration) *DelayTransport {
	if base == nil {
		base = http.DefaultTransport
	}

	return &DelayTransport{
		Base:  base,
		Delay: delay,
	}
}

// NewDelayTransportWithFunc creates a delay transport with a custom delay function
func NewDelayTransportWithFunc(base http.RoundTripper, delayFunc func(*http.Request) time.Duration) *DelayTransport {
	if base == nil {
		base = http.DefaultTransport
	}

	return &DelayTransport{
		Base:      base,
		DelayFunc: delayFunc,
	}
}

// RoundTrip implements http.RoundTripper
func (t *DelayTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Determine delay
	delay := t.Delay
	if t.DelayFunc != nil {
		delay = t.DelayFunc(req)
	}

	// Apply delay if configured
	if delay > 0 {
		slog.Debug("applying request delay",
			"delay", delay,
			"url", req.URL.String(),
			"method", req.Method)

		select {
		case <-time.After(delay):
			// Delay completed
		case <-req.Context().Done():
			// Request cancelled during delay
			return nil, req.Context().Err()
		}
	}

	// Execute request
	return t.Base.RoundTrip(req)
}
