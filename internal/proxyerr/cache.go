// Package errors defines structured error types with HTTP status codes and machine-readable error codes.
package proxyerr

// Cache error constructors

// CacheMissError creates a cache miss error
func CacheMissError(key string) *ProxyError {
	return New(ErrCodeCacheMiss, "cache miss").
		WithDetail("key", key)
}

// CacheWriteError creates a cache write error
func CacheWriteError(key string, cause error) *ProxyError {
	return Wrap(ErrCodeCacheWrite, "failed to write to cache", cause).
		WithDetail("key", key)
}

// CacheReadError creates a cache read error
func CacheReadError(key string, cause error) *ProxyError {
	return Wrap(ErrCodeCacheRead, "failed to read from cache", cause).
		WithDetail("key", key)
}

// CacheExpiredError creates a cache expired error
func CacheExpiredError(key string) *ProxyError {
	return New(ErrCodeCacheExpired, "cache entry expired").
		WithDetail("key", key)
}
