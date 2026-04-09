// Package maxmind integrates MaxMind GeoIP databases for geographic request metadata.
package maxmind

import "errors"

var (
	// ErrUnsupportedDriver is a sentinel error for unsupported driver conditions.
	ErrUnsupportedDriver = errors.New("maxmind: unsupported driver")
	// ErrInvalidSettings is a sentinel error for invalid settings conditions.
	ErrInvalidSettings   = errors.New("maxmind: invalid settings")
)
