// Package objectcache implements an in-memory object cache with TTL expiration and size limits.
package objectcache

import "errors"

var (
	// ErrInvalidDuration is a sentinel error for invalid duration conditions.
	ErrInvalidDuration   = errors.New("objectcache: invalid duration")
	// ErrInvalidInterval is a sentinel error for invalid interval conditions.
	ErrInvalidInterval   = errors.New("objectcache: invalid interval")
	// ErrInvalidMaxObjects is a sentinel error for invalid max objects conditions.
	ErrInvalidMaxObjects = errors.New("objectcache: invalid max objects")
	// ErrInvalidMaxMemory is a sentinel error for invalid max memory conditions.
	ErrInvalidMaxMemory  = errors.New("objectcache: invalid max memory")
)
