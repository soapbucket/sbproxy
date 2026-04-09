// Package messenger provides a pluggable notification system for alerts and event delivery.
package messenger

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
type ConstructorFn func(Settings) (Messenger, error)

// Register registers .
func Register(driver string, fn ConstructorFn) {
	constructorsMu.Lock()
	constructors[driver] = fn
	constructorsMu.Unlock()
}

// NewMessenger creates and initializes a new Messenger.
func NewMessenger(settings Settings) (Messenger, error) {
	constructorsMu.RLock()
	fn, ok := constructors[settings.Driver]
	constructorsMu.RUnlock()

	if !ok {
		slog.Error("unsupported driver", "driver", settings.Driver)
		return nil, ErrUnsupportedDriver
	}

	messenger, err := fn(settings)
	if err != nil {
		return nil, err
	}

	// Apply metrics wrapper if enabled
	if settings.EnableMetrics {
		messenger = NewMetricsMessenger(messenger, settings.Driver)
	}

	// Apply tracing wrapper if enabled
	if settings.EnableTracing {
		messenger = NewTracedMessenger(messenger)
	}

	return messenger, nil
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
