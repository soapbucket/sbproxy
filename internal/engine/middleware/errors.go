// Package middleware contains HTTP middleware for authentication, rate limiting, logging, and request processing.
package middleware

import "errors"

// Sentinel errors for hot-path middleware to avoid per-call allocations.
var (
	// ErrConfigNotReachable is a sentinel error for config not reachable conditions.
	ErrConfigNotReachable   = errors.New("config not reachable")
	// ErrHijackerNotSupported is a sentinel error for hijacker not supported conditions.
	ErrHijackerNotSupported = errors.New("underlying ResponseWriter does not implement http.Hijacker")
)
