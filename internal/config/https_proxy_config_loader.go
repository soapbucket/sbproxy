// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

// AIProvidersConfig holds the structure of ai_providers.yml
type AIProvidersConfig struct {
	Providers []AIProviderConfig `yaml:"providers"`
}

// ConfigurationManager manages loading and caching of HTTPS proxy configurations
type ConfigurationManager struct {
	aiRegistry      *AIRegistry
	loadedProviders bool
	mu              sync.RWMutex
}

// NewConfigurationManager creates a new configuration manager
func NewConfigurationManager() *ConfigurationManager {
	return &ConfigurationManager{
		aiRegistry:      NewAIRegistry(),
		loadedProviders: false,
	}
}

// LoadAIProvidersFromFile loads AI providers from a YAML file
func (cm *ConfigurationManager) LoadAIProvidersFromFile(filepath string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if filepath == "" {
		slog.Debug("no AI providers file specified")
		return nil
	}

	// Read file
	data, err := os.ReadFile(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Warn("AI providers file not found", "path", filepath)
			return nil
		}
		return fmt.Errorf("failed to read AI providers file: %w", err)
	}

	// Parse YAML
	var config AIProvidersConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse AI providers YAML: %w", wrapYAMLError(err))
	}

	// Register providers
	if len(config.Providers) > 0 {
		if err := cm.aiRegistry.RegisterMultiple(config.Providers); err != nil {
			return fmt.Errorf("failed to register AI providers: %w", err)
		}
		slog.Info("loaded AI providers from file", "count", len(config.Providers), "path", filepath)
	}

	cm.loadedProviders = true
	return nil
}

// GetAIRegistry returns the AI provider registry (thread-safe)
func (cm *ConfigurationManager) GetAIRegistry() *AIRegistry {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.aiRegistry
}

// LoadDefaults loads default AI providers.
// This is called if no configuration files are specified.
func (cm *ConfigurationManager) LoadDefaults() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Register some common AI providers
	defaultProviders := []AIProviderConfig{
		{
			Type:      "openai",
			Name:      "OpenAI",
			Hostnames: []string{"api.openai.com", "api.openai-api.com"},
			Ports:     []int{443},
			Endpoints: []string{"/v1/chat/completions", "/v1/completions", "/v1/embeddings", "/v1/responses"},
		},
		{
			Type:      "anthropic",
			Name:      "Anthropic",
			Hostnames: []string{"api.anthropic.com"},
			Ports:     []int{443},
			Endpoints: []string{"/v1/messages", "/v1/complete"},
		},
		{
			Type:      "google",
			Name:      "Google",
			Hostnames: []string{"generativelanguage.googleapis.com"},
			Ports:     []int{443},
			Endpoints: []string{"/v1beta/models"},
		},
		{
			Type:      "cohere",
			Name:      "Cohere",
			Hostnames: []string{"api.cohere.ai"},
			Ports:     []int{443},
			Endpoints: []string{"/v1/generate", "/v1/embed"},
		},
	}

	if err := cm.aiRegistry.RegisterMultiple(defaultProviders); err != nil {
		return fmt.Errorf("failed to register default providers: %w", err)
	}
	cm.loadedProviders = true

	slog.Info("loaded default AI providers", "providers", len(defaultProviders))

	return nil
}

// IsLoaded checks if configuration has been loaded
func (cm *ConfigurationManager) IsLoaded() bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.loadedProviders
}

// Reset clears all loaded configurations
func (cm *ConfigurationManager) Reset() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.aiRegistry = NewAIRegistry()
	cm.loadedProviders = false
}

// LoadStatistics holds configuration loading statistics.
type LoadStatistics struct {
	ProvidersLoaded bool
	ProviderCount   int
}

// GetStatistics returns configuration loading statistics
func (cm *ConfigurationManager) GetStatistics() LoadStatistics {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return LoadStatistics{
		ProvidersLoaded: cm.loadedProviders,
		ProviderCount:   len(cm.aiRegistry.GetAll()),
	}
}
