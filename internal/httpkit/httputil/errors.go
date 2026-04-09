// Package httputil defines HTTP constants, header names, and shared request/response utilities.
package httputil

import (
	"errors"
)

var (
	// ErrHTTPUtilServiceNotInitialized is a sentinel error for http util service not initialized conditions.
	ErrHTTPUtilServiceNotInitialized = errors.New("httputil: service not initialized")
)
