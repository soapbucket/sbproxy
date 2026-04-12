// Package manager defines the Manager interface for coordinating proxy lifecycle and configuration reloads.
package manager

import "errors"

var (
	// ErrInvalidSessionConfiguration is a sentinel error for invalid session configuration conditions.
	ErrInvalidSessionConfiguration = errors.New("manager:invalid session configuration")
	// ErrInvalidCompressionLevel is a sentinel error for invalid compression level conditions.
	ErrInvalidCompressionLevel = errors.New("manager:invalid compression level")
	// ErrInvalidSettings is a sentinel error for invalid settings conditions.
	ErrInvalidSettings = errors.New("manager:invalid settings")
)
