// Package service manages the HTTP server lifecycle including graceful shutdown and TLS configuration.
package service

import (
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/soapbucket/sbproxy/internal/config"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// CompiledConfigManager manages an atomic pointer to the current CompiledConfig
// snapshot. The hot path (ServeHTTP) uses only atomic Load + map lookup with no
// mutex contention. Config reloads build a new CompiledConfig, swap it in via
// Store, and schedule cleanup of the old snapshot after a grace period.
type CompiledConfigManager struct {
	current atomic.Pointer[config.CompiledConfig]

	// gracePeriod is the delay before cleaning up a replaced CompiledConfig.
	// In-flight requests that loaded the old pointer may still be using it,
	// so we wait before calling Cleanup on the old origins.
	gracePeriod time.Duration
}

// DefaultGracePeriod is the default time to wait before cleaning up a replaced
// CompiledConfig snapshot. This allows in-flight requests to finish.
const DefaultGracePeriod = 30 * time.Second

// NewCompiledConfigManager creates a new manager with the given grace period.
// If gracePeriod is zero, DefaultGracePeriod is used.
func NewCompiledConfigManager(gracePeriod time.Duration) *CompiledConfigManager {
	if gracePeriod == 0 {
		gracePeriod = DefaultGracePeriod
	}
	return &CompiledConfigManager{
		gracePeriod: gracePeriod,
	}
}

// Load returns the current CompiledConfig snapshot. This is the hot-path
// method - it performs a single atomic load with no locks or allocations.
// Returns nil if no config has been stored yet.
func (m *CompiledConfigManager) Load() *config.CompiledConfig {
	return m.current.Load()
}

// Swap atomically replaces the current CompiledConfig with a new one.
// The old config's origins are cleaned up after the grace period to allow
// in-flight requests to complete. Swap is safe to call from any goroutine.
func (m *CompiledConfigManager) Swap(next *config.CompiledConfig) {
	old := m.current.Swap(next)

	originCount := 0
	if next != nil {
		originCount = len(next.Origins())
	}

	if old == nil {
		slog.Info("compiled config initialized",
			"origin_count", originCount)
		metric.ConfigReloadWithDuration("compiled_swap", 0)
		return
	}

	slog.Info("compiled config swapped",
		"origin_count", originCount,
		"grace_period", m.gracePeriod)
	metric.ConfigReloadWithDuration("compiled_swap", 0)

	// Schedule cleanup of the old config after the grace period.
	// In-flight requests that already loaded the old pointer can still
	// reference it during this window.
	go m.scheduleCleanup(old, m.gracePeriod)
}

// scheduleCleanup waits for the grace period then calls Cleanup on every
// origin in the old config. This runs in its own goroutine.
func (m *CompiledConfigManager) scheduleCleanup(old *config.CompiledConfig, delay time.Duration) {
	if old == nil {
		return
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()
	<-timer.C

	origins := old.Origins()
	for hostname, origin := range origins {
		origin.Cleanup()
		slog.Debug("cleaned up old compiled origin", "hostname", hostname)
	}
	slog.Info("old compiled config cleanup complete",
		"origin_count", len(origins))
}

// LookupOrigin is a convenience method that loads the current snapshot and
// looks up the origin by hostname. Returns nil if no config is loaded or the
// hostname is not found.
func (m *CompiledConfigManager) LookupOrigin(host string) *config.CompiledOrigin {
	cc := m.current.Load()
	if cc == nil {
		return nil
	}
	return cc.Lookup(host)
}

// AddOrigin atomically adds a single compiled origin to the current snapshot.
// This is used by the compile-on-demand path to cache database-loaded origins
// so that subsequent requests hit the fast path. If there is no current snapshot,
// a new one is created. The operation is performed via a CAS loop to avoid lost
// updates when concurrent requests compile different origins simultaneously.
func (m *CompiledConfigManager) AddOrigin(origin *config.CompiledOrigin) {
	if origin == nil {
		return
	}
	for {
		old := m.current.Load()

		var oldOrigins map[string]*config.CompiledOrigin
		if old != nil {
			oldOrigins = old.Origins()
		}

		// Build a new origins map with the added origin.
		newOrigins := make(map[string]*config.CompiledOrigin, len(oldOrigins)+1)
		for k, v := range oldOrigins {
			newOrigins[k] = v
		}
		newOrigins[origin.Hostname()] = origin

		next := config.NewCompiledConfig(newOrigins)
		if m.current.CompareAndSwap(old, next) {
			slog.Info("added compiled origin on demand",
				"hostname", origin.Hostname(),
				"origin_id", origin.ID(),
				"total_origins", len(newOrigins))
			return
		}
		// CAS failed - another goroutine swapped; retry with fresh snapshot.
	}
}
