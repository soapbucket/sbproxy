// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bytes"
	"regexp"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/httpkit/bufferpool"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// MaxPoolBufferSize is the maximum buffer capacity that will be returned to the pool.
// Buffers exceeding this size are discarded and left for GC to reclaim,
// preventing unbounded pool growth from occasional large allocations.
const MaxPoolBufferSize = 1 << 20 // 1MB

// Buffer pools for reducing allocations and improving performance
// Now using adaptive buffer pool for optimal memory utilization
var (
	// Adaptive buffer pool (initialized in InitBufferPools)
	adaptivePool *bufferpool.AdaptiveBufferPool

	// bytesBufferPool provides reusable bytes.Buffer for string building and JSON operations
	bytesBufferPool = sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}

	// stringSlicePool provides reusable string slices for collecting keys/values
	stringSlicePool = sync.Pool{
		New: func() interface{} {
			slice := make([]string, 0, 10)
			return &slice
		},
	}

	// mapPool provides reusable maps for temporary operations
	mapPool = sync.Pool{
		New: func() interface{} {
			return make(map[string]interface{}, 16)
		},
	}

	// regexCache caches compiled regex patterns to avoid recompilation
	// This is critical for high-throughput scenarios with repeated patterns
	regexCache   = make(map[string]*regexp.Regexp, 100)
	regexCacheMu sync.RWMutex
	maxRegexCacheSize = 1000 // Limit cache size to prevent memory bloat
)

// InitBufferPools initializes the adaptive buffer pool
// This should be called once during application startup
func InitBufferPools() {
	config := bufferpool.DefaultAdaptiveConfig()
	// Customize config based on expected workload
	config.AdjustInterval = 5 * time.Minute
	config.TargetCoverage = 0.90
	config.HistorySize = 10000
	
	adaptivePool = bufferpool.NewAdaptiveBufferPool(config)
	
	// Share the adaptive pool with zerocopy package
	// This is done via import to avoid circular dependency
	// Note: zerocopy.InitBufferPools must be called separately if needed
}

// GetAdaptivePool returns the global adaptive buffer pool instance
// This allows other packages to use the same pool
func GetAdaptivePool() *bufferpool.AdaptiveBufferPool {
	return adaptivePool
}

// ShutdownBufferPools shuts down the adaptive buffer pool
// This should be called during graceful shutdown
func ShutdownBufferPools() {
	if adaptivePool != nil {
		adaptivePool.Shutdown()
	}
}

// GetBufferPoolStats returns statistics about the buffer pool
func GetBufferPoolStats() bufferpool.AdaptiveBufferPoolStats {
	if adaptivePool != nil {
		return adaptivePool.Stats()
	}
	return bufferpool.AdaptiveBufferPoolStats{}
}

// getBuffer gets a buffer from the adaptive pool
// The caller must call putBuffer when done to return it to the pool
func getBuffer() *[]byte {
	// Default to 64KB for typical HTTP bodies
	if adaptivePool != nil {
		return adaptivePool.Get(64 * 1024)
	}
	// Fallback to direct allocation if pool not initialized
	buf := make([]byte, 0, 64*1024)
	return &buf
}

// putBuffer returns a buffer to the adaptive pool after resetting it.
// Buffers exceeding MaxPoolBufferSize are discarded to prevent unbounded pool growth.
func putBuffer(buf *[]byte) {
	if buf != nil && adaptivePool != nil {
		if cap(*buf) > MaxPoolBufferSize {
			metric.PoolOversizedDiscard()
			return // Let GC reclaim oversized buffers
		}
		// AdaptiveBufferPool.Put() handles buffer clearing for security
		adaptivePool.Put(buf)
	}
}

// getSmallBuffer gets a small buffer from the adaptive pool
// The caller must call putSmallBuffer when done to return it to the pool
func getSmallBuffer() *[]byte {
	// 4KB for small operations
	if adaptivePool != nil {
		return adaptivePool.Get(4 * 1024)
	}
	// Fallback
	buf := make([]byte, 0, 4*1024)
	return &buf
}

// putSmallBuffer returns a small buffer to the adaptive pool after resetting it.
// Buffers exceeding MaxPoolBufferSize are discarded to prevent unbounded pool growth.
func putSmallBuffer(buf *[]byte) {
	if buf != nil && adaptivePool != nil {
		if cap(*buf) > MaxPoolBufferSize {
			metric.PoolOversizedDiscard()
			return // Let GC reclaim oversized buffers
		}
		// AdaptiveBufferPool.Put() handles buffer clearing for security
		adaptivePool.Put(buf)
	}
}

// getBytesBuffer gets a bytes.Buffer from the pool
// The caller must call putBytesBuffer when done to return it to the pool
func getBytesBuffer() *bytes.Buffer {
	return bytesBufferPool.Get().(*bytes.Buffer)
}

// putBytesBuffer returns a bytes.Buffer to the pool after resetting it
// Only buffers with reasonable capacity are returned to prevent memory bloat
func putBytesBuffer(buf *bytes.Buffer) {
	if buf != nil {
		buf.Reset() // Clear the buffer
		// Only return to pool if capacity is reasonable (< 1MB)
		if buf.Cap() <= 1024*1024 {
			bytesBufferPool.Put(buf)
		}
	}
}

// getStringSlice gets a string slice from the pool
// The caller must call putStringSlice when done to return it to the pool
func getStringSlice() *[]string {
	return stringSlicePool.Get().(*[]string)
}

// putStringSlice returns a string slice to the pool after resetting it
func putStringSlice(slice *[]string) {
	if slice != nil {
		// Clear the slice but keep capacity
		*slice = (*slice)[:0]
		// Only return to pool if capacity is reasonable (< 1000 elements)
		if cap(*slice) <= 1000 {
			stringSlicePool.Put(slice)
		}
	}
}

// GetMap gets a map from the pool.
// The caller must call PutMap when done to return it to the pool.
func GetMap() map[string]interface{} {
	return mapPool.Get().(map[string]interface{})
}

// getMap is the unexported alias for backward compatibility within this package.
func getMap() map[string]interface{} {
	return mapPool.Get().(map[string]interface{})
}

// PutMap returns a map to the pool after clearing it.
func PutMap(m map[string]interface{}) {
	putMap(m)
}

// putMap is the unexported version for backward compatibility within this package.
func putMap(m map[string]interface{}) {
	if m != nil {
		// Check size before clearing (to prevent returning very large maps)
		size := len(m)
		
		// Clear the map
		for k := range m {
			delete(m, k)
		}
		
		// Only return to pool if original size was reasonable (< 100 entries)
		// This prevents memory bloat from very large maps
		if size <= 100 {
			mapPool.Put(m)
		}
	}
}

// getCompiledRegex gets or compiles a regex pattern with caching.
// This function is hot path - called for every regex replacement operation.
// Uses a two-level locking strategy for optimal performance:
// - Fast path: RLock for cache hits (most common case)
// - Slow path: Lock for cache misses (infrequent)
//
//go:inline
func getCompiledRegex(pattern string) (*regexp.Regexp, error) {
	// Fast path: check cache with read lock
	regexCacheMu.RLock()
	if re, ok := regexCache[pattern]; ok {
		regexCacheMu.RUnlock()
		return re, nil
	}
	regexCacheMu.RUnlock()

	// Slow path: compile and cache with write lock
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	regexCacheMu.Lock()
	// Double-check in case another goroutine compiled it
	if existing, ok := regexCache[pattern]; ok {
		regexCacheMu.Unlock()
		return existing, nil
	}
	// Limit cache size to prevent memory bloat
	if len(regexCache) < maxRegexCacheSize {
		regexCache[pattern] = re
	}
	regexCacheMu.Unlock()

	return re, nil
}

// clearRegexCache clears the regex cache (useful for testing or memory management)
func clearRegexCache() {
	regexCacheMu.Lock()
	regexCache = make(map[string]*regexp.Regexp, 100)
	regexCacheMu.Unlock()
}

// getRegexCacheSize returns the current size of the regex cache (useful for monitoring)
func getRegexCacheSize() int {
	regexCacheMu.RLock()
	size := len(regexCache)
	regexCacheMu.RUnlock()
	return size
}

