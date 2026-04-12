// Package dns implements a DNS resolution cache to reduce lookup latency for upstream hosts.
package dns

import (
	"log/slog"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

var (
	globalResolver *Resolver
	resolverMutex  sync.RWMutex
	metricsStopCh  chan struct{} // Signals the metrics reporting goroutine to stop
)

// DNSCacheSettings represents DNS cache configuration (duplicated here to avoid import cycle)
type DNSCacheSettings struct {
	Enabled           bool
	MaxEntries        int
	DefaultTTL        time.Duration
	NegativeTTL       time.Duration
	ServeStaleOnError bool
	BackgroundRefresh bool
}

// InitGlobalResolver initializes the global DNS resolver from configuration
func InitGlobalResolver(config DNSCacheSettings) {
	resolverMutex.Lock()
	defer resolverMutex.Unlock()

	cacheConfig := CacheConfig(config)

	// Stop any previously running metrics goroutine before re-initializing
	if metricsStopCh != nil {
		close(metricsStopCh)
	}
	metricsStopCh = make(chan struct{})

	cache := NewCache(cacheConfig)
	globalResolver = NewResolver(cache)

	if config.Enabled {
		slog.Info("DNS cache initialized",
			"max_entries", config.MaxEntries,
			"default_ttl", config.DefaultTTL,
			"negative_ttl", config.NegativeTTL,
			"serve_stale_on_error", config.ServeStaleOnError,
			"background_refresh", config.BackgroundRefresh)
	} else {
		slog.Info("DNS cache disabled")
	}

	// Start metrics reporting goroutine
	go reportMetrics(metricsStopCh)
}

// GetGlobalResolver returns the global DNS resolver
func GetGlobalResolver() *Resolver {
	resolverMutex.RLock()
	defer resolverMutex.RUnlock()
	return globalResolver
}

// StopGlobalResolver stops the global DNS resolver's background goroutines
// (cache refresh loop and metrics reporting).
func StopGlobalResolver() {
	resolverMutex.Lock()
	defer resolverMutex.Unlock()

	if metricsStopCh != nil {
		close(metricsStopCh)
		metricsStopCh = nil
	}

	if globalResolver != nil && globalResolver.cache != nil {
		globalResolver.cache.Stop()
	}

	slog.Info("global DNS resolver stopped")
}

// reportMetrics periodically reports DNS cache metrics
func reportMetrics(stopCh chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			resolverMutex.RLock()
			resolver := globalResolver
			resolverMutex.RUnlock()

			if resolver != nil && resolver.GetCache() != nil {
				stats := resolver.GetCache().GetStats()
				metric.DNSCacheSizeSet(stats.Size)
			}
		case <-stopCh:
			slog.Info("DNS metrics reporting stopped")
			return
		}
	}
}
