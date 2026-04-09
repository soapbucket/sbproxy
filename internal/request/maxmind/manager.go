// Package maxmind integrates MaxMind GeoIP databases for geographic request metadata.
package maxmind

import (
	"log/slog"
	"sync"
)

var (
	constructors   = make(map[string]ConstructorFn)
	constructorsMu sync.RWMutex
)

// Register registers .
func Register(driver string, fn ConstructorFn) {
	constructorsMu.Lock()
	constructors[driver] = fn
	constructorsMu.Unlock()
}

// ConstructorFn is a function type for constructor fn callbacks.
type ConstructorFn func(Settings) (Manager, error)

// NewManager creates a new IP database manager
func NewManager(settings Settings) (Manager, error) {
	slog.Debug("creating maxmind manager", "settings", settings)
	if settings.Driver == "" {
		return NoopManager, nil
	}

	constructorsMu.RLock()
	fn, ok := constructors[settings.Driver]
	constructorsMu.RUnlock()
	if !ok {
		return nil, ErrUnsupportedDriver
	}

	manager, err := fn(settings)
	if err != nil {
		return nil, err
	}

	// Apply metrics wrapper if enabled
	if settings.EnableMetrics {
		manager = NewMetricsManager(manager, settings.Driver)
	}

	// Apply tracing wrapper if enabled
	if settings.EnableTracing {
		manager = NewTracedManager(manager)
	}

	return manager, nil
}

// AvailableDrivers performs the available drivers operation.
func AvailableDrivers() []string {
	var names []string

	constructorsMu.RLock()
	for name := range constructors {
		names = append(names, name)
	}
	constructorsMu.RUnlock()
	return names
}
