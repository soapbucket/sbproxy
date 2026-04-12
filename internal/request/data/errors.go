// Package requestdata builds and propagates per-request metadata through the proxy pipeline.
package requestdata

import "errors"

var (
	// ErrInvalidRequestID is a sentinel error for invalid request id conditions.
	ErrInvalidRequestID = errors.New("requestid: invalid request ID")
	// ErrInvalidLevel is a sentinel error for invalid level conditions.
	ErrInvalidLevel = errors.New("requestid: invalid level")
	// ErrMaxDepthExceeded is a sentinel error for max depth exceeded conditions.
	ErrMaxDepthExceeded = errors.New("requestid: max depth exceeded")
)
