// Package handler contains the core HTTP request handler that orchestrates the proxy pipeline.
package handler

import "net/http"

// ModifyResponseFn is a function type for modify response fn callbacks.
type ModifyResponseFn func(*http.Response) error

// ErrorHandlerFn is a function type for error handler fn callbacks.
type ErrorHandlerFn func(http.ResponseWriter, *http.Request, error)

// NullHandler is a variable for null handler.
var NullHandler = http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
