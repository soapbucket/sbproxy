// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
package httputil

import (
	"io"
	"net/http"
)

// NewResponse creates and initializes a new Response.
func NewResponse(req *http.Request, statusCode int, body io.ReadCloser) *http.Response {
	return &http.Response{
		Request:    req,
		StatusCode: statusCode,
		Header:     make(http.Header),
		Body:       body,
	}
}

// EmptyResponse performs the empty response operation.
func EmptyResponse(req *http.Request) *http.Response {
	return NewResponse(req, http.StatusNoContent, http.NoBody)
}
