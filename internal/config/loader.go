// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/soapbucket/sbproxy/internal/security/crypto"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// maxConfigBytes is the maximum allowed size for configuration data (10 MB).
// Prevents denial-of-service via oversized YAML/JSON payloads.
const maxConfigBytes = 10 * 1024 * 1024

// Load performs the load operation.
func Load(data []byte) (*Config, error) {
	return LoadWithContext(context.Background(), data)
}

func detectFormat(data []byte) string {
	for _, b := range data {
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			continue
		}
		if b == '{' || b == '[' {
			return "json"
		}
		return "yaml"
	}
	return "json"
}

// wrapYAMLError enriches go-yaml v3 errors with line-specific detail.
// yaml.TypeError contains per-field messages that include line numbers,
// which are invaluable for debugging misconfigured YAML files.
func wrapYAMLError(err error) error {
	var typeErr *yaml.TypeError
	if errors.As(err, &typeErr) {
		return fmt.Errorf("yaml type error: %s", strings.Join(typeErr.Errors, "; "))
	}
	return err
}

func yamlToJSON(data []byte) ([]byte, error) {
	var raw any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, wrapYAMLError(err)
	}
	return json.Marshal(raw)
}

// LoadWithContext performs the load with context operation.
func LoadWithContext(ctx context.Context, data []byte) (*Config, error) {
	// Guard against oversized payloads (YAML bombs, etc.)
	if len(data) > maxConfigBytes {
		return nil, fmt.Errorf("config: payload too large (%d bytes, max %d)", len(data), maxConfigBytes)
	}

	// Detect format and convert YAML to JSON if needed
	if detectFormat(data) == "yaml" {
		converted, err := yamlToJSON(data)
		if err != nil {
			return nil, fmt.Errorf("config: yaml conversion failed: %w", err)
		}
		data = converted
	}
	// First pass: Load secrets configuration and vault definitions
	// Secrets can be either a single provider object (old format, has "type" key)
	// or a map[string]string of name->reference pairs (new vault format).
	var preConfig struct {
		Secrets json.RawMessage            `json:"secrets,omitempty"`
		Vaults  map[string]VaultDefinition `json:"vaults,omitempty"`
	}
	if err := json.Unmarshal(data, &preConfig); err != nil {
		metric.ConfigError("unknown", "parse_error")
		return nil, fmt.Errorf("failed to pre-parse config for secrets: %w", err)
	}

	// Handle case where secrets might be null or empty
	if len(preConfig.Secrets) == 0 || string(preConfig.Secrets) == "null" {
		preConfig.Secrets = nil
	}

	// Detect secrets format: old provider (has "type" key) vs new map
	isNewSecretsFormat := false
	var newSecretsMap map[string]string
	if len(preConfig.Secrets) > 0 {
		// Try to detect format by checking for "type" key
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(preConfig.Secrets, &probe); err == nil {
			if _, hasType := probe["type"]; !hasType {
				// No "type" key - this is the new map[string]string format
				if err := json.Unmarshal(preConfig.Secrets, &newSecretsMap); err == nil {
					isNewSecretsFormat = true
				}
			}
		}
	}

	// Load secrets and get the values
	var allSecrets map[string]string
	var secretsManager *SecretsManager
	var secretsConfig SecretsConfig

	if isNewSecretsFormat {
		slog.Info("detected new vault-based secrets format", "secret_count", len(newSecretsMap))
		// New format secrets are stored in SecretsMap and resolved via VaultManager
		// during configloader propagation. No provider loading needed here.
	} else if len(preConfig.Secrets) > 0 {
		slog.Info("loading secrets before config parsing (legacy provider format)")
		var err error
		secretsConfig, err = LoadSecretsConfig(preConfig.Secrets)
		if err != nil {
			metric.ConfigError("unknown", "secrets_config_error")
			return nil, fmt.Errorf("failed to load secrets config: %w", err)
		}

		// Load secrets from provider (for substitution and field processing)
		allSecrets, err = secretsConfig.GetSecrets(ctx)
		if err != nil {
			metric.ConfigError("unknown", "secrets_load_error")
			return nil, fmt.Errorf("failed to load secrets from provider: %w", err)
		}

		// Create a SecretsManager wrapper for field processing
		secretsManager = NewSecretsManager()
		id := fmt.Sprintf("%s_0", secretsConfig.GetType())
		if err := secretsManager.AddProvider(id, secretsConfig); err != nil {
			metric.ConfigError("unknown", "secrets_provider_error")
			return nil, fmt.Errorf("failed to add secrets provider: %w", err)
		}
		secretsManager.allSecrets = allSecrets

		slog.Info("loaded secrets for substitution", "total_secrets", len(allSecrets))
	}

	// Note: Secret substitution using ${VAR_NAME} has been removed.
	// Secrets are now accessed via template variables: {{secrets.key}}
	// Secret fields marked with secret:"true" are processed during field processing,
	// and template variables are resolved at runtime when the config is used.

	// Initialize decryptor from environment
	// Decryptor is required for processing encrypted secret fields
	decryptor, err := crypto.NewDecryptorFromEnv()
	if err != nil {
		// Log warning - decryptor may not be needed if all secrets are loaded from providers
		slog.Warn("failed to initialize decryptor (encrypted secrets will not be supported)", "error", err)
		decryptor = nil
	}

	// Second pass: Parse the full configuration with substituted secrets
	cfg := new(Config)
	if err := json.Unmarshal(data, cfg); err != nil {
		metric.ConfigError("unknown", "unmarshal_error")
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Note: Secrets config is already loaded and initialized in UnmarshalJSON
	// If we loaded secrets earlier for substitution, the config should already have them
	// We only need to ensure the secrets are loaded if they weren't loaded during UnmarshalJSON
	if secretsConfig != nil && cfg.secrets == nil {
		// This shouldn't happen if UnmarshalJSON worked correctly, but handle it as a fallback
		slog.Warn("secrets config was loaded for substitution but not set during unmarshaling",
			"hostname", cfg.Hostname,
			"origin_id", cfg.ID)
		cfg.secrets = secretsConfig
	} else if secretsConfig != nil && cfg.secrets != nil {
		// Both exist - the one from UnmarshalJSON should be used (it's already initialized)
		// But we can verify they're the same type
		if secretsConfig.GetType() != cfg.secrets.GetType() {
			slog.Warn("secrets config type mismatch",
				"hostname", cfg.Hostname,
				"origin_id", cfg.ID,
				"loader_type", secretsConfig.GetType(),
				"unmarshal_type", cfg.secrets.GetType())
		}
	}

	// Process secret fields after unmarshaling
	if err := ProcessSecretFields(cfg, secretsManager, decryptor); err != nil {
		metric.ConfigError("unknown", "secret_fields_error")
		return nil, fmt.Errorf("failed to process secret fields: %w", err)
	}

	// Store new-format secrets map and vault definitions on the config
	if isNewSecretsFormat {
		cfg.SecretsMap = newSecretsMap
		// Clear the raw Secrets field so legacy code path is not triggered
		cfg.Secrets = nil
		cfg.secrets = nil
		slog.Info("stored vault secrets map on config",
			"hostname", cfg.Hostname,
			"secret_count", len(newSecretsMap),
			"vault_count", len(cfg.Vaults))
	}

	// Validate and process config-level variables
	if len(cfg.Variables) > 0 {
		if err := ValidateVariables(cfg.Variables); err != nil {
			metric.ConfigError(cfg.Hostname, "variables_validation_error")
			return nil, fmt.Errorf("invalid variables: %w", err)
		}
		slog.Info("loaded config variables", "hostname", cfg.Hostname, "variable_count", len(cfg.Variables))
	}

	// Validate required fields before returning the config
	if err := cfg.Validate(); err != nil {
		metric.ConfigError(cfg.Hostname, "validation_error")
		return nil, err
	}

	return cfg, nil
}
