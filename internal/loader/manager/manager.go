// Package manager defines the Manager interface for coordinating proxy lifecycle and configuration reloads.
package manager

import (
	"context"
	"log/slog"

	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/security/crypto"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
	"github.com/soapbucket/sbproxy/internal/platform/storage"
)

// validateSettings validates the provided settings
func validateSettings(settings GlobalSettings) error {
	// Validate cacher settings
	if len(settings.CacherSettings) == 0 {
		return ErrInvalidSettings
	}

	// Validate compression level
	if settings.CompressionLevel < 0 || settings.CompressionLevel > 9 {
		return ErrInvalidCompressionLevel
	}

	return nil
}

// Initialize initializes the manager with the provided settings
// It performs validation and initializes all required components
func NewManager(ctx context.Context, settings GlobalSettings) (Manager, error) {
	var err error

	// Validate settings
	if err = validateSettings(settings); err != nil {
		slog.Error("invalid settings provided", "error", err)
		return nil, err
	}

	m := &managerImpl{
		ctx:      ctx,
		settings: settings,
	}

	// Initialize storage (default to noop if no driver configured)
	if settings.StorageSettings.Driver == "" {
		settings.StorageSettings.Driver = "noop"
		slog.Debug("no storage driver configured, defaulting to noop")
	}
	var storage storage.Storage
	storage, err = initStorage(settings.StorageSettings)
	if err != nil {
		slog.Error("failed to initialize storage", "error", err)
		return nil, err
	}
	m.storage = storage

	// Initialize events messenger (default to noop if no driver configured)
	if settings.MessengerSettings.Driver == "" {
		settings.MessengerSettings.Driver = "noop"
		slog.Debug("no messenger driver configured, defaulting to noop")
	}
	var messenger messenger.Messenger
	messenger, err = initEvents(settings.MessengerSettings)
	if err != nil {
		slog.Error("failed to initialize messenger", "error", err)
		return nil, err
	}
	m.messenger = messenger

	// Initialize crypto (auto-generate ephemeral key if none configured)
	if settings.CryptoSettings.Params == nil {
		settings.CryptoSettings.Params = make(map[string]string)
	}
	if settings.CryptoSettings.Params["encryption_key"] == "" {
		key, keyErr := crypto.GenerateKey()
		if keyErr != nil {
			slog.Error("failed to generate ephemeral crypto key", "error", keyErr)
			return nil, keyErr
		}
		settings.CryptoSettings.Params["encryption_key"] = key
		slog.Debug("no crypto key configured, using ephemeral key")
	}
	var c crypto.Crypto
	c, err = initCrypto(settings.CryptoSettings)
	if err != nil {
		slog.Error("failed to initialize crypto", "error", err)
		return nil, err
	}
	m.crypto = c

	// Initialize caches
	var caches map[CacheLevel]cacher.Cacher
	caches, err = initCachers(settings.CacherSettings)
	if err != nil {
		slog.Error("failed to initialize caches", "error", err)
		return nil, err
	}
	m.caches = caches

	// Initialize session cache
	var session SessionCache
	session, err = initSessionCache(caches[L1Cache], caches[L2Cache], settings.L2CacheTimeout, ctx)
	if err != nil {
		slog.Error("failed to initialize session cache", "error", err)
		return nil, err
	}
	m.session = session

	slog.Info("manager initialized")

	return m, nil
}

type managerImpl struct {
	settings  GlobalSettings
	storage   storage.Storage
	messenger messenger.Messenger
	session   SessionCache
	caches    map[CacheLevel]cacher.Cacher
	crypto    crypto.Crypto
	ctx       context.Context
	
	// Worker pools (optional - for goroutine management)
	callbackPool WorkerPool
	cachePool    WorkerPool
}

// GetServerContext returns the server context for the managerImpl.
func (m *managerImpl) GetServerContext() context.Context {
	return m.ctx
}

// Close releases resources held by the managerImpl.
func (m *managerImpl) Close() error {
	var errors []error

	// Close storage
	if m.storage != nil {
		if err := m.storage.Close(); err != nil {
			slog.Error("error closing storage", "error", err)
			errors = append(errors, err)
		}
	}

	// Close events
	if m.messenger != nil {
		if err := m.messenger.Close(); err != nil {
			slog.Error("error closing messenger", "error", err)
			errors = append(errors, err)
		}
	}

	// Close caches
	for level, cache := range m.caches {
		if cache != nil {
			if err := cache.Close(); err != nil {
				slog.Error("error closing cache", "level", level, "error", err)
				errors = append(errors, err)
			}
		}
	}

	if len(errors) > 0 {
		return errors[0] // Return first error
	}

	slog.Info("manager closed")
	return nil
}

// GetStorage returns the storage for the managerImpl.
func (m *managerImpl) GetStorage() storage.Storage {
	return m.storage
}

// GetGlobalSettings returns the global settings for the managerImpl.
func (m *managerImpl) GetGlobalSettings() GlobalSettings {
	return m.settings
}

// GetCache returns the cache for the managerImpl.
func (m *managerImpl) GetCache(level CacheLevel) cacher.Cacher {
	return m.caches[level]
}

// GetMessenger returns the messenger for the managerImpl.
func (m *managerImpl) GetMessenger() messenger.Messenger {
	return m.messenger
}

// GetSessionCache returns the session cache for the managerImpl.
func (m *managerImpl) GetSessionCache() SessionCache {
	return m.session
}

// GetCallbackPool returns the callback pool for the managerImpl.
func (m *managerImpl) GetCallbackPool() WorkerPool {
	return m.callbackPool
}

// GetCachePool returns the cache pool for the managerImpl.
func (m *managerImpl) GetCachePool() WorkerPool {
	return m.cachePool
}

func initStorage(settings storage.Settings) (storage.Storage, error) {
	return storage.NewStorage(settings)
}

func initEvents(settings messenger.Settings) (messenger.Messenger, error) {
	return messenger.NewMessenger(settings)
}

func initCachers(settings map[CacheLevel]cacher.Settings) (map[CacheLevel]cacher.Cacher, error) {
	cachers := make(map[CacheLevel]cacher.Cacher)
	for level, setting := range settings {

		cacher, err := initCacher(setting)
		if err != nil {
			return nil, err
		}
		cachers[level] = cacher

	}
	return cachers, nil
}

func initCrypto(settings crypto.Settings) (crypto.Crypto, error) {

	return crypto.NewCrypto(settings)

}

func initCacher(settings cacher.Settings) (cacher.Cacher, error) {
	return cacher.NewCacher(settings)
}

