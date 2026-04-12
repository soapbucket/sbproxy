// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"io"
	"net/http"
	"strings"

	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// MaxConnections represents a max connections.
type MaxConnections struct {
	http.RoundTripper

	connections chan struct{}
}

// RoundTrip performs the round trip operation on the MaxConnections.
// It respects the request context to avoid blocking indefinitely when
// the connection pool is full and the request is cancelled.
func (m *MaxConnections) RoundTrip(req *http.Request) (*http.Response, error) {
	// Early exit if context is already done.
	if err := req.Context().Err(); err != nil {
		return nil, err
	}

	select {
	case m.connections <- struct{}{}:
		// acquired slot
	case <-req.Context().Done():
		metric.MaxConnectionsRejected()
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Status:     "503 Service Unavailable",
			Header: http.Header{
				"Content-Type": {"text/plain; charset=utf-8"},
				"Retry-After":  {"1"},
			},
			Body:    io.NopCloser(strings.NewReader("503 Service Unavailable: connection limit reached\n")),
			Request: req,
		}, nil
	}
	defer func() { <-m.connections }()

	return m.RoundTripper.RoundTrip(req)
}

// NewMaxConnections creates and initializes a new MaxConnections.
func NewMaxConnections(tr http.RoundTripper, max int) http.RoundTripper {
	if max <= 0 {
		max = 1
	}

	return &MaxConnections{
		RoundTripper: tr,
		connections:  make(chan struct{}, max),
	}
}
