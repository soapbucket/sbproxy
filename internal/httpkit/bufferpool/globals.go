// Package bufferpool provides a sync.Pool-based buffer recycling mechanism to reduce GC pressure.
package bufferpool

import "time"

// MaxPoolBufferSize is the maximum buffer capacity that will be returned to the pool.
// Buffers exceeding this size are discarded and left for GC to reclaim,
// preventing unbounded pool growth from occasional large allocations.
const MaxPoolBufferSize = 1 << 20 // 1MB

// Adaptive buffer pool (initialized in InitBufferPools)
var adaptivePool *AdaptiveBufferPool

// InitBufferPools initializes the adaptive buffer pool.
// This should be called once during application startup.
func InitBufferPools() {
	config := DefaultAdaptiveConfig()
	// Customize config based on expected workload
	config.AdjustInterval = 5 * time.Minute
	config.TargetCoverage = 0.90
	config.HistorySize = 10000

	adaptivePool = NewAdaptiveBufferPool(config)
}

// GetAdaptivePool returns the global adaptive buffer pool instance.
// This allows other packages to use the same pool.
func GetAdaptivePool() *AdaptiveBufferPool {
	return adaptivePool
}

// ShutdownBufferPools shuts down the adaptive buffer pool.
// This should be called during graceful shutdown.
func ShutdownBufferPools() {
	if adaptivePool != nil {
		adaptivePool.Shutdown()
	}
}
