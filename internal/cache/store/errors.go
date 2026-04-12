// Package cacher implements multi-tier response caching with support for memory and Redis backends.
package cacher

import "errors"

var (
	// ErrUnsupportedDriver is a sentinel error for unsupported driver conditions.
	ErrUnsupportedDriver = errors.New("cacher: unsupported driver")
	// ErrNotFound is a sentinel error for not found conditions.
	ErrNotFound = errors.New("cacher: not found")
	// ErrInvalidConfiguration is a sentinel error for invalid configuration conditions.
	ErrInvalidConfiguration = errors.New("cacher: invalid configuration")
	// ErrInvalidSettingsFile is a sentinel error for invalid settings file conditions.
	ErrInvalidSettingsFile = errors.New("cacher: invalid settings file")
	// ErrInvalidPrefix is a sentinel error for invalid prefix conditions.
	ErrInvalidPrefix = errors.New("cacher: invalid prefix")
	// ErrInvalidKey is a sentinel error for invalid key conditions.
	ErrInvalidKey = errors.New("cacher: invalid key")
	// ErrInvalidType is a sentinel error for invalid type conditions.
	ErrInvalidType = errors.New("cacher: invalid type")
	// ErrInvalidExpires is a sentinel error for invalid expires conditions.
	ErrInvalidExpires = errors.New("cacher: invalid expires")
	// ErrInvalidDuration is a sentinel error for invalid duration conditions.
	ErrInvalidDuration = errors.New("cacher: invalid duration")
	// ErrInvalidInterval is a sentinel error for invalid interval conditions.
	ErrInvalidInterval = errors.New("cacher: invalid interval")
)
