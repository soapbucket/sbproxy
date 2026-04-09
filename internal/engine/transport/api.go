// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"net/http"
)

// API represents a api.
type API struct {
	tr http.RoundTripper
}

// APIResponse defines the interface for api response operations.
type APIResponse interface {
	CreateAPIResponse(req *http.Request) (*http.Response, error)
	IsValidAPIRequest(req *http.Request) bool
}

// NewAPITransport creates and initializes a new APITransport.
func NewAPITransport(tr http.RoundTripper, altAPIPath string, r APIResponse) http.RoundTripper {
	return RoundTripFn(func(req *http.Request) (*http.Response, error) {
		if !r.IsValidAPIRequest(req) {
			return tr.RoundTrip(req)
		}
		return r.CreateAPIResponse(req)
	})
}
