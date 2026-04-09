// Package uaparser parses User-Agent strings to extract browser, OS, and device information.
package uaparser

import "errors"

var (
	// ErrUnsupportedDriver is a sentinel error for unsupported driver conditions.
	ErrUnsupportedDriver = errors.New("uaparser: unsupported driver")
	// ErrInvalidSettings is a sentinel error for invalid settings conditions.
	ErrInvalidSettings   = errors.New("uaparser: invalid settings")
)
