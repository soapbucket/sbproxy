package config

import (
	"fmt"
	"log/slog"
	"os"

	"gopkg.in/yaml.v3"
)

// AIProvidersFile represents the structure of the ai_providers.yml file.
type AIProvidersFile struct {
	Providers []AIProviderConfig `yaml:"providers"`
}

// globalAIProviders holds providers loaded from the YAML file at startup.
// Used as the default when HTTPS proxy origins don't specify known_ai_origins.
var globalAIProviders []AIProviderConfig

// LoadAIProviders loads AI provider definitions from a YAML file.
// Call during server startup to replace the hardcoded defaults.
func LoadAIProviders(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read AI providers file %s: %w", filePath, err)
	}

	var file AIProvidersFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("failed to parse AI providers file %s: %w", filePath, wrapYAMLError(err))
	}

	if len(file.Providers) == 0 {
		slog.Warn("AI providers file loaded but contains no providers", "file", filePath)
		return nil
	}

	globalAIProviders = file.Providers
	slog.Info("AI providers loaded from file", "file", filePath, "count", len(file.Providers))
	return nil
}

// GetAIProviders returns the loaded AI providers. If none were loaded from file,
// returns the hardcoded defaults for backward compatibility.
func GetAIProviders() []AIProviderConfig {
	if len(globalAIProviders) > 0 {
		return globalAIProviders
	}
	return defaultHTTPSProxyAIOrigins()
}
