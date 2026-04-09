// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"log/slog"

	"github.com/soapbucket/sbproxy/internal/engine/transport"
)

var validStorageKinds = map[string]bool{
	"s3":     true,
	"azure":  true,
	"google": true,
	"swift":  true,
	"b2":     true,
}

func init() {
	loaderFns[TypeStorage] = LoadStorageConfig
}

// StorageTypedConfig represents the storage backend configuration
type StorageTypedConfig struct {
	StorageConfig
}

// LoadStorageConfig loads a storage backend configuration
func LoadStorageConfig(data []byte) (ActionConfig, error) {
	slog.Debug("loading storage config")

	cfg := new(StorageTypedConfig)
	if err := json.Unmarshal(data, cfg); err != nil {
		slog.Error("failed to unmarshal storage config", "error", err)
		return nil, err
	}

	// Validate required fields
	if cfg.Kind == "" {
		slog.Error("storage kind is required")
		return nil, ErrStorageKindRequired
	}

	if cfg.Bucket == "" {
		slog.Error("storage bucket is required")
		return nil, ErrStorageBucketRequired
	}

	// Validate kind (optimized: use map lookup instead of switch)
	if !validStorageKinds[cfg.Kind] {
		slog.Error("invalid storage kind", "kind", cfg.Kind)
		return nil, ErrInvalidStorageKind
	}

	settings := buildStorageSettings(&cfg.StorageConfig)
	cache := transport.GetGlobalLocationCache()
	tr := transport.NewStorageWithCache(cfg.Kind, settings, nil, cache)
	cfg.tr = tr

	slog.Debug("storage config loaded", "kind", cfg.Kind, "bucket", cfg.Bucket)
	return cfg, nil
}

// buildStorageSettings converts storage config to transport settings
func buildStorageSettings(cfg *StorageConfig) transport.Settings {
	settings := transport.Settings{
		"bucket": cfg.Bucket,
	}

	if cfg.Key != "" {
		settings["key"] = cfg.Key
	}
	if cfg.Secret != "" {
		settings["secret"] = cfg.Secret
	}
	if cfg.Region != "" {
		settings["region"] = cfg.Region
	}
	if cfg.ProjectID != "" {
		settings["projectId"] = cfg.ProjectID
	}
	if cfg.Account != "" {
		settings["account"] = cfg.Account
	}
	if cfg.Scopes != "" {
		settings["scopes"] = cfg.Scopes
	}
	if cfg.TenantName != "" {
		settings["tenant"] = cfg.TenantName
	}
	if cfg.TenantAuthURL != "" {
		settings["tenantAuthURL"] = cfg.TenantAuthURL
	}

	return settings
}
