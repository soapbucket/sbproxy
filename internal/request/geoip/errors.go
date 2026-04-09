// Package geoip provides GeoIP database integration for geographic request metadata.
package geoip

import "errors"

var (
	// ErrUnsupportedDriver is a sentinel error for unsupported driver conditions.
	ErrUnsupportedDriver = errors.New("geoip: unsupported driver")
	// ErrInvalidSettings is a sentinel error for invalid settings conditions.
	ErrInvalidSettings   = errors.New("geoip: invalid settings")
)
