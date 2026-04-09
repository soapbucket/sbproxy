// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"net/http"
)

// logSender is defined in wrap.go

// ModifyResponseFn is a function type for modify response fn callbacks.
type ModifyResponseFn func(resp *http.Response) error

// RoundTripFn is a function type for round trip fn callbacks.
type RoundTripFn func(*http.Request) (*http.Response, error)

// RoundTrip performs the round trip operation on the RoundTripFn.
func (fn RoundTripFn) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

// Null is a variable for null.
var Null = RoundTripFn(func(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode:    http.StatusNoContent,
		Header:        make(http.Header),
		Body:          http.NoBody,
		Request:       req,
		ContentLength: -1,
	}, nil
})
