// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
)

var (
	// Match ${VAR_NAME} pattern
	secretVarPattern = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)\}`)
)

// SubstituteSecrets replaces ${VAR_NAME} patterns in the config with values from secrets
// Secret values are JSON-escaped to ensure valid JSON output
func SubstituteSecrets(configData []byte, secrets map[string]string) ([]byte, error) {
	if len(secrets) == 0 {
		return configData, nil
	}

	configStr := string(configData)

	// Track missing secrets
	var missingSecrets []string

	// Replace all ${VAR_NAME} patterns
	result := secretVarPattern.ReplaceAllStringFunc(configStr, func(match string) string {
		// Extract variable name (remove ${ and })
		varName := match[2 : len(match)-1]

		// Look up secret value
		value, exists := secrets[varName]
		if !exists {
			slog.Warn("secret not found for variable substitution", "variable", varName)
			missingSecrets = append(missingSecrets, varName)
			return match // Keep original if not found
		}

		slog.Debug("substituting secret variable", "variable", varName)
		// JSON-escape the value to ensure valid JSON output
		escapedValue, err := json.Marshal(value)
		if err != nil {
			slog.Warn("failed to JSON-escape secret value, using raw value", "variable", varName, "error", err)
			return value // Fall back to raw value if marshaling fails
		}
		// Remove surrounding quotes added by json.Marshal for string values
		escapedStr := string(escapedValue)
		if len(escapedStr) >= 2 && escapedStr[0] == '"' && escapedStr[len(escapedStr)-1] == '"' {
			return escapedStr[1 : len(escapedStr)-1]
		}
		return escapedStr
	})

	if len(missingSecrets) > 0 {
		return nil, fmt.Errorf("missing secrets for variables: %s", strings.Join(missingSecrets, ", "))
	}

	return []byte(result), nil
}

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
