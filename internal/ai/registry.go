// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	_ "embed"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed providers.yaml
var embeddedProviders []byte

// ProviderRegistry holds provider and model definitions loaded from YAML.
type ProviderRegistry struct {
	Version   int                    `yaml:"version"`
	Providers map[string]ProviderDef `yaml:"providers"`
	mu        sync.RWMutex
}

// ProviderDef describes a provider's connection and model catalog.
type ProviderDef struct {
	DisplayName string              `yaml:"display_name"`
	BaseURL     string              `yaml:"base_url"`
	AuthHeader  string              `yaml:"auth_header"`
	AuthPrefix  string              `yaml:"auth_prefix"`
	Format      string              `yaml:"format"`
	Requires    []string            `yaml:"requires,omitempty"`
	DocsURL     string              `yaml:"docs_url,omitempty"`
	Models      map[string]ModelDef `yaml:"models"`
}

// ModelDef describes a model's capabilities (pricing is handled by the pricing package).
type ModelDef struct {
	DisplayName       string `yaml:"display_name,omitempty"`
	Tokenizer         string `yaml:"tokenizer,omitempty"`
	ContextWindow     int    `yaml:"context_window,omitempty"`
	SupportsVision    bool   `yaml:"supports_vision,omitempty"`
	IsReasoning       bool   `yaml:"is_reasoning,omitempty"`
	SupportsStreaming *bool  `yaml:"supports_streaming,omitempty"`
	SupportsTools     *bool  `yaml:"supports_tools,omitempty"`
}

// global registry
var (
	globalRegistry   *ProviderRegistry
	globalRegistryMu sync.RWMutex
)

// SetRegistry sets the global provider registry.
func SetRegistry(r *ProviderRegistry) {
	globalRegistryMu.Lock()
	defer globalRegistryMu.Unlock()
	globalRegistry = r
}

// GetRegistry returns the global provider registry.
func GetRegistry() *ProviderRegistry {
	globalRegistryMu.RLock()
	defer globalRegistryMu.RUnlock()
	return globalRegistry
}

// LoadRegistry loads the provider registry from a file path, falling back to embedded data.
// If path is provided but the file doesn't exist, falls back to embedded data with a warning.
func LoadRegistry(path string) (*ProviderRegistry, error) {
	var data []byte
	var source string

	if path != "" {
		var err error
		data, err = os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				slog.Warn("provider registry file not found, using embedded defaults", "path", path)
				data = embeddedProviders
				source = "embedded (file not found)"
			} else {
				return nil, fmt.Errorf("registry: read file: %w", err)
			}
		} else {
			source = path
		}
	} else {
		data = embeddedProviders
		source = "embedded"
	}

	var reg ProviderRegistry
	if err := yaml.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("registry: parse %s: %w", source, err)
	}

	modelCount := 0
	for _, p := range reg.Providers {
		modelCount += len(p.Models)
	}
	slog.Info("provider registry loaded",
		"source", source,
		"providers", len(reg.Providers),
		"models", modelCount,
	)

	return &reg, nil
}

// GetProvider returns a provider definition by slug.
func (r *ProviderRegistry) GetProvider(slug string) (ProviderDef, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.Providers[slug]
	return p, ok
}

// GetModel returns a model definition by name, searching all providers.
func (r *ProviderRegistry) GetModel(model string) (ModelDef, string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for providerSlug, p := range r.Providers {
		if m, ok := p.Models[model]; ok {
			return m, providerSlug, true
		}
	}
	return ModelDef{}, "", false
}

// GetModelTokenizer returns the tokenizer encoding for a model.
func (r *ProviderRegistry) GetModelTokenizer(model string) string {
	m, _, ok := r.GetModel(model)
	if !ok {
		return ""
	}
	return m.Tokenizer
}

// ListProviders returns all provider slugs.
func (r *ProviderRegistry) ListProviders() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	slugs := make([]string, 0, len(r.Providers))
	for slug := range r.Providers {
		slugs = append(slugs, slug)
	}
	return slugs
}

// ModelCount returns the total number of models across all providers.
func (r *ProviderRegistry) ModelCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	count := 0
	for _, p := range r.Providers {
		count += len(p.Models)
	}
	return count
}

// ApplyDefaults fills in ProviderConfig fields from the registry if not already set.
func (r *ProviderRegistry) ApplyDefaults(cfg *ProviderConfig) {
	if cfg == nil {
		return
	}
	slug := cfg.GetType()
	pdef, ok := r.GetProvider(slug)
	if !ok {
		return
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = pdef.BaseURL
	}
	// Set format type for provider matching
	if cfg.Type == "" && pdef.Format != "" {
		cfg.Type = pdef.Format
	}
	// Apply auth header defaults
	if pdef.AuthHeader != "" && cfg.Headers == nil {
		cfg.Headers = map[string]string{}
	}
}

// FormatForProvider returns the format handler name for a provider slug.
func (r *ProviderRegistry) FormatForProvider(slug string) string {
	pdef, ok := r.GetProvider(slug)
	if !ok {
		return ""
	}
	return pdef.Format
}

// TokenizerForModel returns the tokenizer for a model, using the registry.
// Falls back to heuristic matching if not found.
func TokenizerForModel(model string) string {
	reg := GetRegistry()
	if reg != nil {
		if tok := reg.GetModelTokenizer(model); tok != "" {
			return tok
		}
	}
	// Fallback to heuristic
	lower := strings.ToLower(model)
	switch {
	case strings.Contains(lower, "gpt-4o"), strings.Contains(lower, "gpt-4-turbo"), strings.Contains(lower, "o1"), strings.Contains(lower, "o3"):
		return "o200k_base"
	case strings.Contains(lower, "gpt-4"), strings.Contains(lower, "gpt-3.5"):
		return "cl100k_base"
	case strings.Contains(lower, "claude"):
		return "cl100k_base"
	default:
		return "estimate"
	}
}
