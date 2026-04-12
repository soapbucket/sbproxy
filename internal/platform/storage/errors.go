// Package storage provides storage backend abstractions for caching and persistence.
package storage

import "errors"

var (
	// ErrUnsupportedDriver is returned when an unsupported storage driver is requested
	ErrUnsupportedDriver = errors.New("storage: unsupported driver")
	// ErrKeyNotFound is returned when a key is not found in the storage
	ErrKeyNotFound = errors.New("storage: key not found")
	// ErrReadOnly is returned when a write operation is attempted on a read-only storage
	ErrReadOnly = errors.New("storage: read-only")
	// ErrInvalidKey is returned when a key is invalid
	ErrInvalidKey = errors.New("storage: invalid key")
	// ErrInvalidConfiguration is returned when configuration is invalid or missing
	ErrInvalidConfiguration = errors.New("storage: invalid configuration")
	// ErrListKeysNotSupported is returned when ListKeys is not supported by the storage driver
	ErrListKeysNotSupported = errors.New("storage: ListKeys not supported")
)
