// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
)

// SecretsType represents the type of secrets provider
type SecretsType string

const (
	// SecretsTypeAWS is a constant for secrets type aws.
	SecretsTypeAWS SecretsType = "aws"
	// SecretsTypeGCP is a constant for secrets type gcp.
	SecretsTypeGCP SecretsType = "gcp"
	// SecretsTypeCallback is a constant for secrets type callback.
	SecretsTypeCallback SecretsType = "callback"
)

var secretsLoaderFns = map[SecretsType]SecretsConfigConstructorFn{}

// SecretsConfig is the interface for secrets providers
type SecretsConfig interface {
	GetType() SecretsType
	Load(ctx context.Context) (map[string]string, error)
	Init(*Config) error
	GetSecrets(ctx context.Context) (map[string]string, error)
	GetCacheDuration() time.Duration
	// Internal methods for Config-level reloading
	getSecrets() map[string]string
	SetSecrets(map[string]string)
}

// BaseSecretsConfig contains common fields for all secrets providers
type BaseSecretsConfig struct {
	Type          SecretsType   `json:"type"`
	ID            string        `json:"id,omitempty"`             // Unique identifier for this secrets provider
	CacheDuration time.Duration `json:"cache_duration,omitempty"` // Duration to cache secrets before reloading

	// Loaded secrets (populated after Load())
	secrets map[string]string
	// Last time secrets were loaded
	lastLoaded time.Time
}

// GetType returns the secrets provider type
func (b *BaseSecretsConfig) GetType() SecretsType {
	return b.Type
}

// Init is a no-op base implementation
func (b *BaseSecretsConfig) Init(config *Config) error {
	return nil
}

// GetSecrets returns the loaded secrets map (internal use)
func (b *BaseSecretsConfig) getSecrets() map[string]string {
	if b.secrets == nil {
		return make(map[string]string)
	}
	return b.secrets
}

// SetSecrets sets the secrets map
func (b *BaseSecretsConfig) SetSecrets(secrets map[string]string) {
	b.secrets = secrets
	b.lastLoaded = time.Now()
}

// GetCacheDuration returns the cache duration for this secrets provider
func (b *BaseSecretsConfig) GetCacheDuration() time.Duration {
	return b.CacheDuration
}

// GetSecrets returns secrets, reloading if cache expired or never loaded
// This is a base implementation that should be overridden by specific implementations
// since BaseSecretsConfig doesn't implement Load() - it's an interface method
// Each secrets config implementation should override this method
func (b *BaseSecretsConfig) GetSecrets(ctx context.Context) (map[string]string, error) {
	// Base implementation - just return cached secrets if available
	// Specific implementations should override this to call their Load() method
	return b.getSecrets(), nil
}

// SecretsConfigConstructorFn is a function type for secrets config constructor fn callbacks.
type SecretsConfigConstructorFn func([]byte) (SecretsConfig, error)

// LoadSecretsConfig loads a secrets configuration from raw JSON
func LoadSecretsConfig(data []byte) (SecretsConfig, error) {
	// Parse cache_duration if present (can be string like "5m" or duration)
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secrets config: %w", err)
	}

	var cacheDuration time.Duration
	if cacheDurStr, ok := raw["cache_duration"].(string); ok {
		var err error
		cacheDuration, err = time.ParseDuration(cacheDurStr)
		if err != nil {
			return nil, fmt.Errorf("invalid cache_duration: %w", err)
		}
		// Remove from raw map so it doesn't interfere with normal unmarshaling
		delete(raw, "cache_duration")
		// Re-marshal without cache_duration
		var err2 error
		data, err2 = json.Marshal(raw)
		if err2 != nil {
			return nil, err2
		}
	}

	var base BaseSecretsConfig
	if err := json.Unmarshal(data, &base); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secrets config: %w", err)
	}

	if base.Type == "" {
		return nil, fmt.Errorf("secrets type is required")
	}

	loaderFn, ok := secretsLoaderFns[base.Type]
	if !ok {
		return nil, fmt.Errorf("unknown secrets type: %s", base.Type)
	}

	secretsCfg, err := loaderFn(data)
	if err != nil {
		return nil, err
	}

	// Set cache_duration on the loaded config if it was parsed from string
	if cacheDuration > 0 {
		// All secrets configs embed BaseSecretsConfig, so we can set it directly
		if baseCfg, ok := secretsCfg.(interface{ SetCacheDuration(time.Duration) }); ok {
			baseCfg.SetCacheDuration(cacheDuration)
		} else {
			// Fallback: use reflection or type assertion
			// Since all configs embed BaseSecretsConfig, we can access it
			if awsCfg, ok := secretsCfg.(*AWSSecretsConfig); ok {
				awsCfg.CacheDuration = cacheDuration
			} else if gcpCfg, ok := secretsCfg.(*GCPSecretsConfig); ok {
				gcpCfg.CacheDuration = cacheDuration
			} else if callbackCfg, ok := secretsCfg.(*CallbackSecretsConfig); ok {
				callbackCfg.CacheDuration = cacheDuration
			}
		}
	}

	return secretsCfg, nil
}

// Secrets is a raw JSON type for unmarshaling
type Secrets json.RawMessage

// UnmarshalJSON implements json.Unmarshaler for Secrets
func (s *Secrets) UnmarshalJSON(data []byte) error {
	*s = Secrets(data)
	return nil
}

// MarshalJSON implements json.Marshaler for Secrets
func (s Secrets) MarshalJSON() ([]byte, error) {
	if s == nil {
		return []byte("null"), nil
	}
	return []byte(s), nil
}

// SecretsManager manages multiple secrets providers
type SecretsManager struct {
	providers map[string]SecretsConfig
	// Combined secrets from all providers
	allSecrets map[string]string
}

// NewSecretsManager creates a new secrets manager
func NewSecretsManager() *SecretsManager {
	return &SecretsManager{
		providers:  make(map[string]SecretsConfig),
		allSecrets: make(map[string]string),
	}
}

// AddProvider adds a secrets provider
func (m *SecretsManager) AddProvider(id string, provider SecretsConfig) error {
	if _, exists := m.providers[id]; exists {
		return fmt.Errorf("secrets provider with ID %s already exists", id)
	}
	m.providers[id] = provider
	return nil
}

// LoadAll loads secrets from all providers
func (m *SecretsManager) LoadAll(ctx context.Context) error {
	for id, provider := range m.providers {
		slog.Info("loading secrets from provider", "provider_id", id, "provider_type", provider.GetType())
		secrets, err := provider.Load(ctx)
		if err != nil {
			return fmt.Errorf("failed to load secrets from provider %s: %w", id, err)
		}

		// Merge secrets into allSecrets
		// Later providers with the same key will override earlier ones
		for key, value := range secrets {
			m.allSecrets[key] = value
		}
		slog.Info("loaded secrets from provider", "provider_id", id, "secret_count", len(secrets))
	}
	return nil
}

// GetSecret retrieves a secret by key
func (m *SecretsManager) GetSecret(key string) (string, bool) {
	value, exists := m.allSecrets[key]
	return value, exists
}

// GetAllSecrets returns all loaded secrets
func (m *SecretsManager) GetAllSecrets() map[string]string {
	// Return a copy to prevent modification
	result := make(map[string]string, len(m.allSecrets))
	for k, v := range m.allSecrets {
		result[k] = v
	}
	return result
}

// ── secrets_reload.go ─────────────────────────────────────────────────────────

// reloadSecretsIfNeeded checks if secrets need to be reloaded based on CacheDuration
// and reloads them if the cache has expired or was never loaded.
func (c *Config) reloadSecretsIfNeeded(ctx context.Context) {
	if c.secrets == nil {
		return
	}

	// If no cache duration is set, keep it for the life of the config in memory (no reload)
	cacheDuration := c.secrets.GetCacheDuration()
	if cacheDuration <= 0 {
		// If never loaded, load now
		if c.secrets.getSecrets() == nil || len(c.secrets.getSecrets()) == 0 {
			slog.Debug("secrets never loaded, loading now",
				"origin_id", c.ID,
				"hostname", c.Hostname,
				"secrets_type", c.secrets.GetType())
			secrets, err := c.secrets.Load(ctx)
			if err != nil {
				slog.Error("secrets load failed",
					"origin_id", c.ID,
					"hostname", c.Hostname,
					"secrets_type", c.secrets.GetType(),
					"error", err)
				return
			}
			c.secrets.SetSecrets(secrets)
			slog.Debug("secrets loaded",
				"origin_id", c.ID,
				"hostname", c.Hostname,
				"secrets_type", c.secrets.GetType(),
				"secret_count", len(secrets))
		}
		return
	}

	// Check if cache duration has expired or secrets were never loaded
	// All secrets configs embed BaseSecretsConfig, so we can access lastLoaded
	// Use type assertion to get the embedded BaseSecretsConfig
	var baseSecrets *BaseSecretsConfig
	switch s := c.secrets.(type) {
	case *AWSSecretsConfig:
		baseSecrets = &s.BaseSecretsConfig
	case *GCPSecretsConfig:
		baseSecrets = &s.BaseSecretsConfig
	case *CallbackSecretsConfig:
		baseSecrets = &s.BaseSecretsConfig
	default:
		slog.Warn("unknown secrets config type, cannot check lastLoaded",
			"origin_id", c.ID,
			"hostname", c.Hostname,
			"secrets_type", c.secrets.GetType())
		return
	}

	shouldReload := false
	if baseSecrets.lastLoaded.IsZero() {
		slog.Debug("secrets never loaded, loading now",
			"origin_id", c.ID,
			"hostname", c.Hostname,
			"secrets_type", c.secrets.GetType())
		shouldReload = true
	} else {
		timeSinceLastLoad := time.Since(baseSecrets.lastLoaded)
		if timeSinceLastLoad >= cacheDuration {
			slog.Debug("secrets cache expired, reloading",
				"origin_id", c.ID,
				"hostname", c.Hostname,
				"time_since_last_load", timeSinceLastLoad,
				"cache_duration", cacheDuration)
			shouldReload = true
		} else {
			slog.Debug("secrets cache still valid",
				"origin_id", c.ID,
				"hostname", c.Hostname,
				"time_since_last_load", timeSinceLastLoad,
				"cache_duration", cacheDuration)
		}
	}

	if !shouldReload {
		return
	}

	// Reload secrets
	secrets, err := c.secrets.Load(ctx)
	if err != nil {
		slog.Error("secrets reload failed",
			"origin_id", c.ID,
			"hostname", c.Hostname,
			"secrets_type", c.secrets.GetType(),
			"error", err)
		// Keep existing secrets on error
		return
	}

	// Update secrets and timestamp
	c.secrets.SetSecrets(secrets)
	slog.Info("secrets reloaded",
		"origin_id", c.ID,
		"hostname", c.Hostname,
		"secrets_type", c.secrets.GetType(),
		"secret_count", len(secrets))
}

// ── secrets_substitution.go ───────────────────────────────────────────────────

// GetSecrets returns all secrets from the config's secrets provider, reloading if needed based on CacheDuration.
// If SecretsConfig.CacheDuration is set and expired, secrets will be reloaded.
// If SecretsConfig.CacheDuration is not set or is 0, secrets are kept for the life of the config in memory.
// Always returns a non-nil map (empty map if no secrets config or if loading fails).
func (c *Config) GetSecrets(ctx context.Context) map[string]string {
	if c.secrets == nil {
		slog.Debug("GetSecrets: no secrets config",
			"origin_id", c.ID,
			"hostname", c.Hostname)
		return make(map[string]string)
	}

	// Reload secrets if needed (handles cache duration check internally)
	c.reloadSecretsIfNeeded(ctx)

	// Return secrets (may be empty map if never loaded or loading failed)
	secrets := c.secrets.getSecrets()
	if len(secrets) == 0 {
		slog.Debug("GetSecrets: secrets map is empty",
			"origin_id", c.ID,
			"hostname", c.Hostname,
			"secrets_type", c.secrets.GetType())
		return make(map[string]string)
	}

	slog.Debug("GetSecrets: returning secrets",
		"origin_id", c.ID,
		"hostname", c.Hostname,
		"secret_count", len(secrets))
	return secrets
}

// ── secrets_enterprise_stubs.go ───────────────────────────────────────────────

// AWSSecretsConfig is a stub for the AWS Secrets Manager provider.
// This type exists to satisfy type assertions; a full implementation
// can be linked in by providing a Load method via build-time injection.
type AWSSecretsConfig struct {
	BaseSecretsConfig
}

// Load is a no-op stub; not available in this build.
func (a *AWSSecretsConfig) Load(_ context.Context) (map[string]string, error) {
	return nil, fmt.Errorf("aws secrets provider is not available in this build")
}

// SetCacheDuration sets the cache duration on the base config.
func (a *AWSSecretsConfig) SetCacheDuration(d time.Duration) {
	a.CacheDuration = d
}

// GCPSecretsConfig is a stub for the GCP Secret Manager provider.
type GCPSecretsConfig struct {
	BaseSecretsConfig
}

// Load is a no-op stub; not available in this build.
func (g *GCPSecretsConfig) Load(_ context.Context) (map[string]string, error) {
	return nil, fmt.Errorf("gcp secrets provider is not available in this build")
}

// SetCacheDuration sets the cache duration on the base config.
func (g *GCPSecretsConfig) SetCacheDuration(d time.Duration) {
	g.CacheDuration = d
}

// CallbackSecretsConfig is a stub for the callback-based secrets provider.
type CallbackSecretsConfig struct {
	BaseSecretsConfig
}

// Load is a no-op stub; not available in this build.
func (c *CallbackSecretsConfig) Load(_ context.Context) (map[string]string, error) {
	return nil, fmt.Errorf("callback secrets provider is not available in this build")
}

// SetCacheDuration sets the cache duration on the base config.
func (c *CallbackSecretsConfig) SetCacheDuration(d time.Duration) {
	c.CacheDuration = d
}
