// Package storage provides storage backend abstractions for caching and persistence.
package storage

import (
	"log/slog"
	"strings"
	"sync"
)

// ConstructorFn is a function type for constructor fn callbacks.
type ConstructorFn func(Settings) (Storage, error)

var (
	constructors   = make(map[string]ConstructorFn)
	constructorsMu sync.RWMutex
)

// Register registers .
func Register(name string, fn ConstructorFn) {
	constructorsMu.Lock()
	constructors[name] = fn
	constructorsMu.Unlock()
	slog.Debug("storage driver registered", "driver", name)
}

// NewStorage creates and initializes a new Storage.
func NewStorage(settings Settings) (Storage, error) {
	constructorsMu.RLock()
	fn, ok := constructors[settings.Driver]
	available := AvailableDrivers()
	constructorsMu.RUnlock()
	if !ok {
		slog.Error("unsupported storage driver", "driver", settings.Driver, "available_drivers", available)
		return nil, ErrUnsupportedDriver
	}

	storage, err := fn(settings)
	if err != nil {
		return nil, err
	}

	// Apply metrics wrapper if enabled
	if settings.EnableMetrics {
		storage = NewMetricsStorage(storage, settings.Driver)
	}

	// Apply tracing wrapper if enabled
	if settings.EnableTracing {
		storage = NewTracedStorage(storage)
	}

	return storage, nil
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

// NewSettingsFromDSN creates a Settings struct from a DSN string.
// Supports various DSN formats:
// - postgres://user:pass@host:port/dbname?sslmode=disable
// - sqlite:///path/to/database.db
// - file:///path/to/file.json
// - cdb:///path/to/file.cdb
func NewSettingsFromDSN(dsn string) (*Settings, error) {
	if dsn == "" {
		return nil, ErrInvalidKey
	}

	// Parse the DSN to extract driver and path
	if strings.HasPrefix(dsn, "postgres://") {
		return &Settings{
			Driver: DriverPostgres,
			Params: map[string]string{
				ParamDSN: dsn,
			},
		}, nil
	}

	if strings.HasPrefix(dsn, "sqlite://") {
		path := strings.TrimPrefix(dsn, "sqlite://")
		return &Settings{
			Driver: DriverSQLite,
			Params: map[string]string{
				ParamPath: path,
			},
		}, nil
	}

	if strings.HasPrefix(dsn, "file://") {
		path := strings.TrimPrefix(dsn, "file://")
		return &Settings{
			Driver: DriverFile,
			Params: map[string]string{
				ParamPath: path,
			},
		}, nil
	}

	if strings.HasPrefix(dsn, "cdb://") {
		path := strings.TrimPrefix(dsn, "cdb://")
		return &Settings{
			Driver: DriverCDB,
			Params: map[string]string{
				ParamPath: path,
			},
		}, nil
	}

	// If no recognized prefix, assume it's a file path for sqlite
	return &Settings{
		Driver: DriverSQLite,
		Params: map[string]string{
			ParamPath: dsn,
		},
	}, nil
}

// NewStorageFromDSN creates a new Storage instance directly from a DSN string.
// This is a convenience function that combines NewSettingsFromDSN and NewStorage.
func NewStorageFromDSN(dsn string) (Storage, error) {
	settings, err := NewSettingsFromDSN(dsn)
	if err != nil {
		return nil, err
	}
	return NewStorage(*settings)
}
