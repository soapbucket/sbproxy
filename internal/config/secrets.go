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
	SecretsTypeAWS       SecretsType = "aws"
	// SecretsTypeGCP is a constant for secrets type gcp.
	SecretsTypeGCP       SecretsType = "gcp"
	// SecretsTypeCallback is a constant for secrets type callback.
	SecretsTypeCallback  SecretsType = "callback"
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
	Type          SecretsType  `json:"type"`
	ID            string       `json:"id,omitempty"` // Unique identifier for this secrets provider
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

