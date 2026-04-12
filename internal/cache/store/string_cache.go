// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
package cacher

import (
	"strings"
	"sync"
)

// StringCache provides a cache for frequently used strings to reduce allocations
// This is particularly useful for header names, content types, and other
// commonly accessed strings in hot paths.
type StringCache struct {
	cache sync.Map // map[string]string
}

var globalStringCache = &StringCache{}

// GetString returns a cached string if available, otherwise returns the input
// and caches it for future use. This reduces allocations for frequently used strings.
func GetString(s string) string {
	if cached, ok := globalStringCache.cache.Load(s); ok {
		return cached.(string)
	}
	globalStringCache.cache.Store(s, s)
	return s
}

// BuilderPool provides a pool of strings.Builder instances to reduce allocations
// in hot paths where string building is frequent.
// This pool works in conjunction with the adaptive buffer pool for optimal sizing.
var BuilderPool = sync.Pool{
	New: func() interface{} {
		return &strings.Builder{}
	},
}

// adaptivePoolGetter allows access to the adaptive buffer pool without creating
// a circular dependency. This is set by the config package during initialization.
var adaptivePoolGetter func() interface{}

// SetAdaptivePoolGetter sets the function to get the adaptive buffer pool.
// This should be called during service initialization to enable adaptive sizing.
func SetAdaptivePoolGetter(getter func() interface{}) {
	adaptivePoolGetter = getter
}

// getOptimalSize uses the adaptive buffer pool to track size patterns for string building.
// The adaptive pool learns optimal buffer sizes based on usage patterns, which helps
// with overall memory optimization. We use the requested size for the builder, but
// track it with the adaptive pool so it can learn patterns.
func getOptimalSize(requestedSize int) int {
	if adaptivePoolGetter == nil {
		return requestedSize
	}

	// Try to get the adaptive pool
	pool := adaptivePoolGetter()
	if pool == nil {
		return requestedSize
	}

	// Track the size pattern with the adaptive pool
	// This helps the pool learn optimal sizes for string building operations
	// The pool's Get() method records the size in its history for future optimization
	if adaptivePool, ok := pool.(interface {
		Get(size int) *[]byte
	}); ok {
		// Get a buffer to track this size pattern (pool records it internally)
		buf := adaptivePool.Get(requestedSize)
		// Use the buffer's capacity (pool may round up to nearest tier)
		optimalSize := cap(*buf)
		// Return the buffer immediately - we only needed it for size tracking
		if putter, ok := pool.(interface {
			Put(buf *[]byte)
		}); ok {
			putter.Put(buf)
		}
		// Return the optimal size (may be rounded up by pool tiers)
		// This helps align builder capacity with pool tier sizes
		return optimalSize
	}

	// Fallback to requested size if pool doesn't match expected interface
	return requestedSize
}

// GetBuilder returns a strings.Builder from the pool.
// The builder is guaranteed to be reset and ready to use.
// Call PutBuilder when done to return it to the pool.
func GetBuilder() *strings.Builder {
	b := BuilderPool.Get().(*strings.Builder)
	// Defensive reset: ensure builder is clean even if it wasn't properly reset when returned
	// This handles edge cases like panics or missed PutBuilder calls
	b.Reset()
	return b
}

// GetBuilderWithSize returns a strings.Builder from the pool, pre-grown to the specified size.
// This uses the adaptive buffer pool to optimize sizing when available.
// The builder is guaranteed to be reset and ready to use.
// Call PutBuilder when done to return it to the pool.
func GetBuilderWithSize(size int) *strings.Builder {
	b := GetBuilder()
	// Use adaptive pool to get optimal size if available
	optimalSize := getOptimalSize(size)
	if optimalSize > 0 {
		b.Grow(optimalSize)
	}
	return b
}

// PutBuilder returns a strings.Builder to the pool.
// The builder is properly reset before being returned to ensure no data leakage.
// Only builders with reasonable capacity are returned to prevent memory bloat.
func PutBuilder(b *strings.Builder) {
	if b == nil {
		return
	}

	// Reset the builder to clear its contents and length
	// This is critical to prevent data leakage between uses
	b.Reset()

	// Check capacity before returning to pool
	// If the builder has grown too large, don't return it to prevent memory bloat
	// This allows the GC to reclaim the memory for oversized builders
	// Note: The adaptive pool handles larger buffers, but strings.Builder has its own
	// internal buffer management, so we cap at a reasonable size for pooling
	if b.Cap() > 1024 {
		return
	}

	// Return the reset builder to the pool
	// The builder is now clean and ready for the next use
	BuilderPool.Put(b)
}

// Additional common HTTP header names (cached to reduce allocations)
// Note: Some headers are already defined in constants.go
var (
	// HeaderContentLength is the HTTP header name for content length.
	HeaderContentLength = GetString("Content-Length")
	// HeaderAuthorization is the HTTP header name for authorization.
	HeaderAuthorization = GetString("Authorization")
	// HeaderAccept is the HTTP header name for accept.
	HeaderAccept = GetString("Accept")
	// HeaderXRequestID is the HTTP header name for x request id.
	HeaderXRequestID = GetString("X-Request-ID")
	// HeaderXForwardedFor is the HTTP header name for x forwarded for.
	HeaderXForwardedFor = GetString("X-Forwarded-For")
	// HeaderXRealIP is the HTTP header name for x real ip.
	HeaderXRealIP = GetString("X-Real-IP")
)

// Additional common content types (cached to reduce allocations)
// Note: Some content types are already defined in constants.go
var (
	// ContentTypeFormURLEnc is a variable for content type form url enc.
	ContentTypeFormURLEnc = GetString("application/x-www-form-urlencoded")
)

// Common HTTP methods (cached to reduce allocations)
var (
	// MethodGET is a variable for method get.
	MethodGET = GetString("GET")
	// MethodPOST is a variable for method post.
	MethodPOST = GetString("POST")
	// MethodPUT is a variable for method put.
	MethodPUT = GetString("PUT")
	// MethodDELETE is a variable for method delete.
	MethodDELETE = GetString("DELETE")
	// MethodPATCH is a variable for method patch.
	MethodPATCH = GetString("PATCH")
	// MethodHEAD is a variable for method head.
	MethodHEAD = GetString("HEAD")
	// MethodOPTIONS is a variable for method options.
	MethodOPTIONS = GetString("OPTIONS")
)
