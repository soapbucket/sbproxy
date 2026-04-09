// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"log/slog"
	"time"
)

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

