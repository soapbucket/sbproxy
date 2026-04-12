// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
package httputil

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// HTTPRequest represents an HTTP request builder
type HTTPRequest struct {
	method  string
	url     string
	headers map[string]string
	body    interface{}
	ctx     context.Context
}

// NewHTTPRequest creates a new HTTP request builder
func NewHTTPRequest(method, url string) *HTTPRequest {
	return &HTTPRequest{
		method:  method,
		url:     url,
		headers: make(map[string]string),
		ctx:     context.Background(),
	}
}

// WithContext sets the request context
func (r *HTTPRequest) WithContext(ctx context.Context) *HTTPRequest {
	r.ctx = ctx
	return r
}

// WithHeader adds a header to the request
func (r *HTTPRequest) WithHeader(key, value string) *HTTPRequest {
	r.headers[key] = value
	return r
}

// WithHeaders adds multiple headers to the request
func (r *HTTPRequest) WithHeaders(headers map[string]string) *HTTPRequest {
	for k, v := range headers {
		r.headers[k] = v
	}
	return r
}

// WithBody sets the request body
func (r *HTTPRequest) WithBody(body interface{}) *HTTPRequest {
	r.body = body
	return r
}

// Build builds the HTTP request
func (r *HTTPRequest) Build() (*http.Request, error) {
	var bodyReader io.Reader

	if r.body != nil {
		switch v := r.body.(type) {
		case string:
			bodyReader = strings.NewReader(v)
		case []byte:
			bodyReader = bytes.NewReader(v)
		case io.Reader:
			bodyReader = v
		default:
			// Assume JSON marshaling
			jsonBody, err := json.Marshal(r.body)
			if err != nil {
				return nil, err
			}
			bodyReader = bytes.NewReader(jsonBody)
			r.headers["Content-Type"] = "application/json"
		}
	}

	req, err := http.NewRequestWithContext(r.ctx, r.method, r.url, bodyReader)
	if err != nil {
		return nil, err
	}

	for k, v := range r.headers {
		req.Header.Set(k, v)
	}

	return req, nil
}

// Do executes the HTTP request
func (r *HTTPRequest) Do(client *http.Client) (*http.Response, error) {
	req, err := r.Build()
	if err != nil {
		return nil, err
	}

	return client.Do(req)
}

// HTTPResponse provides utilities for handling HTTP responses
type HTTPResponse struct {
	*http.Response
}

// JSON decodes the response body as JSON
func (r *HTTPResponse) JSON(v interface{}) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

// String returns the response body as a string
func (r *HTTPResponse) String() (string, error) {
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// Bytes returns the response body as bytes
func (r *HTTPResponse) Bytes() ([]byte, error) {
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

// IsSuccess returns true if the status code is 2xx
func (r *HTTPResponse) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

// IsRedirect returns true if the status code is 3xx
func (r *HTTPResponse) IsRedirect() bool {
	return r.StatusCode >= 300 && r.StatusCode < 400
}

// IsClientError returns true if the status code is 4xx
func (r *HTTPResponse) IsClientError() bool {
	return r.StatusCode >= 400 && r.StatusCode < 500
}

// IsServerError returns true if the status code is 5xx
func (r *HTTPResponse) IsServerError() bool {
	return r.StatusCode >= 500 && r.StatusCode < 600
}

// WrapResponse wraps an http.Response
func WrapResponse(resp *http.Response) *HTTPResponse {
	return &HTTPResponse{Response: resp}
}
