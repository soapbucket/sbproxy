// Package configloader loads and validates proxy configuration from the management API or local files.
package configloader

import "errors"

var (
	// ErrConfigNotFound is a sentinel error for config not found conditions.
	ErrConfigNotFound = errors.New("configloader: config not found")
)
