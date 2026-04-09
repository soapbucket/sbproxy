package rag

import (
	"fmt"
	"log/slog"
	"sync"
)

// ProviderConfig holds the configuration for a single RAG provider.
type ProviderConfig struct {
	Type    string            `json:"type"`    // Provider type: pinecone, vectara, bedrock, vertex, ragie, cloudflare, nuclia, cohere, redis
	Enabled bool              `json:"enabled"` // Whether this provider is active
	Config  map[string]string `json:"config" secret:"true"` // Provider-specific key-value configuration (secret values resolved via vault/encrypted/template)
}

// SecretConfigKeys returns the config key names that contain secrets for the given provider type.
// These keys should be resolved through the secrets system (vault, encrypted, template) and
// must never be logged or exposed in plaintext.
func SecretConfigKeys(providerType string) []string {
	switch providerType {
	case "pinecone":
		return []string{"api_key"}
	case "vectara":
		return []string{"api_key"}
	case "bedrock":
		return []string{"access_key_id", "secret_access_key", "session_token"}
	case "vertex":
		return []string{"credentials_json"}
	case "ragie":
		return []string{"api_key"}
	case "cloudflare":
		return []string{"api_token"}
	case "nuclia":
		return []string{"api_key"}
	case "cohere":
		return []string{"api_key"}
	case "redis":
		return []string{"redis_url", "embedding_api_key", "llm_api_key"}
	default:
		return nil
	}
}

// RedactConfig returns a copy of the config map with secret values masked.
// Use this for logging or diagnostic output.
func RedactConfig(providerType string, config map[string]string) map[string]string {
	redacted := make(map[string]string, len(config))
	secretKeys := make(map[string]bool)
	for _, k := range SecretConfigKeys(providerType) {
		secretKeys[k] = true
	}
	for k, v := range config {
		if secretKeys[k] && v != "" {
			if len(v) > 4 {
				redacted[k] = v[:2] + "***" + v[len(v)-2:]
			} else {
				redacted[k] = "***"
			}
		} else {
			redacted[k] = v
		}
	}
	return redacted
}

// ProviderFactory is a function that creates a Provider from config.
type ProviderFactory func(config map[string]string) (Provider, error)

// Registry manages provider factories and active provider instances.
type Registry struct {
	factories map[string]ProviderFactory
	providers map[string]Provider
	mu        sync.RWMutex
}

// NewRegistry creates a new provider registry.
func NewRegistry() *Registry {
	return &Registry{
		factories: make(map[string]ProviderFactory),
		providers: make(map[string]Provider),
	}
}

// RegisterFactory registers a provider factory for a given type.
func (r *Registry) RegisterFactory(providerType string, factory ProviderFactory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[providerType] = factory
}

// Create instantiates a provider from config and registers it.
// Secret config values are redacted in log output.
func (r *Registry) Create(config ProviderConfig) (Provider, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	factory, ok := r.factories[config.Type]
	if !ok {
		return nil, fmt.Errorf("unknown provider type: %q", config.Type)
	}

	slog.Info("creating RAG provider",
		"type", config.Type,
		"config", RedactConfig(config.Type, config.Config),
	)

	provider, err := factory(config.Config)
	if err != nil {
		return nil, fmt.Errorf("create provider %q: %w", config.Type, err)
	}

	r.providers[config.Type] = provider
	return provider, nil
}

// Get returns a registered provider by type.
func (r *Registry) Get(providerType string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[providerType]
	return p, ok
}

// List returns all registered provider names.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	return names
}

// SupportedTypes returns all registered factory types.
func (r *Registry) SupportedTypes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	types := make([]string, 0, len(r.factories))
	for t := range r.factories {
		types = append(types, t)
	}
	return types
}

// CloseAll closes all active providers.
func (r *Registry) CloseAll() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var firstErr error
	for name, p := range r.providers {
		if err := p.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close provider %q: %w", name, err)
		}
	}
	r.providers = make(map[string]Provider)
	return firstErr
}

// DefaultRegistry creates a registry with all built-in provider factories registered.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.RegisterFactory("pinecone", NewPineconeProvider)
	r.RegisterFactory("vectara", NewVectaraProvider)
	r.RegisterFactory("bedrock", NewBedrockProvider)
	r.RegisterFactory("vertex", NewVertexProvider)
	r.RegisterFactory("ragie", NewRagieProvider)
	r.RegisterFactory("cloudflare", NewCloudflareProvider)
	r.RegisterFactory("nuclia", NewNucliaProvider)
	r.RegisterFactory("cohere", NewCohereProvider)
	r.RegisterFactory("redis", NewRedisProvider)
	return r
}
