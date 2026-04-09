// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"fmt"
	"strings"
	"sync"
)

// AIRegistry manages detection and matching of known AI providers
type AIRegistry struct {
	providers map[string]*AIProviderConfig
	mu        sync.RWMutex
}

// NewAIRegistry creates a new AI provider registry
func NewAIRegistry() *AIRegistry {
	return &AIRegistry{
		providers: make(map[string]*AIProviderConfig),
	}
}

// Register adds an AI provider to the registry
func (r *AIRegistry) Register(provider *AIProviderConfig) error {
	if provider == nil {
		return fmt.Errorf("provider cannot be nil")
	}
	if provider.Type == "" {
		return fmt.Errorf("provider type cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.providers[strings.ToLower(provider.Type)] = provider
	return nil
}

// RegisterMultiple adds multiple AI providers to the registry
func (r *AIRegistry) RegisterMultiple(providers []AIProviderConfig) error {
	for i := range providers {
		if err := r.Register(&providers[i]); err != nil {
			return err
		}
	}
	return nil
}

// MatchHost checks if the given host matches any known AI provider
// Returns the matched provider, its name, and whether a match was found
func (r *AIRegistry) MatchHost(host string) (*AIProviderConfig, string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	host = strings.ToLower(host)

	// First check exact hostname matches across all providers
	for providerType, provider := range r.providers {
		for _, hostname := range provider.Hostnames {
			if strings.EqualFold(hostname, host) {
				return provider, providerType, true
			}
			// Also check without port
			hostWithoutPort := strings.Split(host, ":")[0]
			if strings.EqualFold(hostname, hostWithoutPort) {
				return provider, providerType, true
			}
		}
	}

	// Check wildcard patterns (e.g., *.openai.com)
	for providerType, provider := range r.providers {
		for _, pattern := range provider.Hostnames {
			if matchWildcard(host, pattern) {
				return provider, providerType, true
			}
		}
	}

	return nil, "", false
}

// MatchPort checks if the given port is used by any AI provider
func (r *AIRegistry) MatchPort(port int) (*AIProviderConfig, string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for providerType, provider := range r.providers {
		if len(provider.Ports) == 0 {
			// If no ports specified, assume default HTTPS port 443
			if port == 443 {
				return provider, providerType, true
			}
			continue
		}

		for _, p := range provider.Ports {
			if p == port {
				return provider, providerType, true
			}
		}
	}

	return nil, "", false
}

// MatchEndpoint checks if the given endpoint path matches any AI provider's known endpoints
func (r *AIRegistry) MatchEndpoint(path string) (*AIProviderConfig, string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	path = strings.ToLower(path)

	for providerType, provider := range r.providers {
		for _, endpoint := range provider.Endpoints {
			if strings.EqualFold(endpoint, path) || strings.HasPrefix(path, strings.ToLower(endpoint)) {
				return provider, providerType, true
			}
		}
	}

	return nil, "", false
}

// Get retrieves a provider by type
func (r *AIRegistry) Get(providerType string) (*AIProviderConfig, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	provider, ok := r.providers[strings.ToLower(providerType)]
	return provider, ok
}

// GetAll returns all registered providers
func (r *AIRegistry) GetAll() []AIProviderConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()

	providers := make([]AIProviderConfig, 0, len(r.providers))
	for _, provider := range r.providers {
		providers = append(providers, *provider)
	}
	return providers
}

// Clear removes all providers from the registry
func (r *AIRegistry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers = make(map[string]*AIProviderConfig)
}

// matchWildcard checks if host matches pattern (e.g., api.openai.com matches *.openai.com)
func matchWildcard(host, pattern string) bool {
	host = strings.ToLower(host)
	pattern = strings.ToLower(pattern)

	// Remove port from host for matching
	hostWithoutPort := strings.Split(host, ":")[0]

	if !strings.Contains(pattern, "*") {
		return hostWithoutPort == pattern
	}

	parts := strings.Split(pattern, "*")
	if len(parts) != 2 {
		return false
	}

	prefix := parts[0]
	suffix := parts[1]

	if prefix != "" && !strings.HasPrefix(hostWithoutPort, prefix) {
		return false
	}

	if suffix != "" && !strings.HasSuffix(hostWithoutPort, suffix) {
		return false
	}

	return true
}
