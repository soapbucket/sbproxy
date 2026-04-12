// Package cacher implements multi-tier response caching with support for memory and Redis backends.
package cacher

import (
	"log/slog"
	"sort"
	"sync"
)

var (
	constructors   = make(map[string]ConstructorFn)
	constructorsMu sync.RWMutex
)

// ConstructorFn is a function type for constructor fn callbacks.
type ConstructorFn func(Settings) (Cacher, error)

// Register registers .
func Register(typeName string, fn ConstructorFn) {
	constructorsMu.Lock()
	constructors[typeName] = fn
	constructorsMu.Unlock()
}

// NewCacher creates and initializes a new Cacher.
func NewCacher(settings Settings) (Cacher, error) {
	if settings.Driver == "" {
		settings.Driver = DriverMemory
	}

	constructorsMu.RLock()
	fn, ok := constructors[settings.Driver]
	constructorsMu.RUnlock()

	if !ok {
		slog.Error("unsupported driver", "driver", settings.Driver)
		return nil, ErrUnsupportedDriver
	}

	cacher, err := fn(settings)
	if err != nil {
		return nil, err
	}

	// Apply metrics wrapper if enabled
	if settings.EnableMetrics {
		cacher = NewMetricsCacher(cacher, settings.Driver)
	}

	// Apply tracing wrapper if enabled
	if settings.EnableTracing {
		cacher = NewTracedManager(cacher)
	}

	return cacher, nil
}

// AvailableDrivers performs the available drivers operation.
func AvailableDrivers() []string {
	var names []string

	constructorsMu.RLock()
	for name := range constructors {
		names = append(names, name)
	}
	constructorsMu.RUnlock()

	sort.Strings(names)
	return names
}
