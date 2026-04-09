package config

import (
	"testing"
)

func TestNewAIRegistry(t *testing.T) {
	registry := NewAIRegistry()
	if registry == nil {
		t.Fatal("NewAIRegistry() returned nil")
	}
	if len(registry.GetAll()) != 0 {
		t.Fatal("NewAIRegistry() should be empty initially")
	}
}

func TestAIRegistryRegister(t *testing.T) {
	registry := NewAIRegistry()

	provider := &AIProviderConfig{
		Type:      "openai",
		Name:      "OpenAI",
		Hostnames: []string{"api.openai.com"},
		Ports:     []int{443},
	}

	err := registry.Register(provider)
	if err != nil {
		t.Fatalf("Register() failed: %v", err)
	}

	retrieved, ok := registry.Get("openai")
	if !ok {
		t.Fatal("Get() returned false for registered provider")
	}
	if retrieved.Type != "openai" {
		t.Errorf("Get() returned wrong type: got %s, want openai", retrieved.Type)
	}
}

func TestAIRegistryRegisterErrors(t *testing.T) {
	registry := NewAIRegistry()

	tests := []struct {
		name        string
		provider    *AIProviderConfig
		expectError bool
	}{
		{
			name:        "nil provider",
			provider:    nil,
			expectError: true,
		},
		{
			name:        "empty type",
			provider:    &AIProviderConfig{Type: ""},
			expectError: true,
		},
		{
			name:        "valid provider",
			provider:    &AIProviderConfig{Type: "test"},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := registry.Register(tt.provider)
			if (err != nil) != tt.expectError {
				t.Errorf("Register() error = %v, expectError = %v", err, tt.expectError)
			}
		})
	}
}

func TestAIRegistryMatchHost(t *testing.T) {
	registry := NewAIRegistry()

	registry.Register(&AIProviderConfig{
		Type:      "openai",
		Name:      "OpenAI",
		Hostnames: []string{"api.openai.com", "*.openai.com"},
	})

	registry.Register(&AIProviderConfig{
		Type:      "anthropic",
		Name:      "Anthropic",
		Hostnames: []string{"api.anthropic.com"},
	})

	tests := []struct {
		name            string
		host            string
		expectFound     bool
		expectType      string
		expectProviderName string
	}{
		{
			name:        "exact match",
			host:        "api.openai.com",
			expectFound: true,
			expectType: "openai",
		},
		{
			name:        "wildcard match",
			host:        "chat.openai.com",
			expectFound: true,
			expectType: "openai",
		},
		{
			name:        "case insensitive",
			host:        "API.OPENAI.COM",
			expectFound: true,
			expectType: "openai",
		},
		{
			name:        "with port",
			host:        "api.openai.com:443",
			expectFound: true,
			expectType: "openai",
		},
		{
			name:        "different provider",
			host:        "api.anthropic.com",
			expectFound: true,
			expectType: "anthropic",
		},
		{
			name:        "no match",
			host:        "api.unknown.com",
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, providerType, found := registry.MatchHost(tt.host)
			if found != tt.expectFound {
				t.Errorf("MatchHost() found = %v, expectFound = %v", found, tt.expectFound)
			}
			if found && providerType != tt.expectType {
				t.Errorf("MatchHost() type = %s, expectType = %s", providerType, tt.expectType)
			}
			if found && provider == nil {
				t.Error("MatchHost() returned nil provider when found = true")
			}
		})
	}
}

func TestAIRegistryMatchPort(t *testing.T) {
	tests := []struct {
		name        string
		port        int
		expectFound bool
		expectType  string
	}{
		{
			name:        "explicit port match",
			port:        443,
			expectFound: true,
			expectType: "openai",
		},
		{
			name:        "alternate port",
			port:        8443,
			expectFound: true,
			expectType: "openai",
		},
		{
			name:        "default port (no explicit ports)",
			port:        443,
			expectFound: true,
		},
		{
			name:        "no match",
			port:        9999,
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create new registry for each test to avoid concurrent access issues
			registry := NewAIRegistry()

			registry.Register(&AIProviderConfig{
				Type:      "openai",
				Hostnames: []string{"api.openai.com"},
				Ports:     []int{443, 8443},
			})

			registry.Register(&AIProviderConfig{
				Type:      "anthropic",
				Hostnames: []string{"api.anthropic.com"},
				Ports:     []int{}, // Default to 443
			})

			provider, _, found := registry.MatchPort(tt.port)
			if found != tt.expectFound {
				t.Errorf("MatchPort() found = %v, expectFound = %v", found, tt.expectFound)
			}
			if found && provider == nil {
				t.Error("MatchPort() returned nil provider when found = true")
			}
		})
	}
}

func TestAIRegistryMatchEndpoint(t *testing.T) {
	registry := NewAIRegistry()

	registry.Register(&AIProviderConfig{
		Type:      "openai",
		Endpoints: []string{"/v1/chat/completions", "/v1/embeddings"},
	})

	tests := []struct {
		name        string
		path        string
		expectFound bool
	}{
		{
			name:        "exact match",
			path:        "/v1/chat/completions",
			expectFound: true,
		},
		{
			name:        "case insensitive",
			path:        "/V1/CHAT/COMPLETIONS",
			expectFound: true,
		},
		{
			name:        "prefix match",
			path:        "/v1/chat/completions?model=gpt4",
			expectFound: true,
		},
		{
			name:        "no match",
			path:        "/v1/unknown",
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, found := registry.MatchEndpoint(tt.path)
			if found != tt.expectFound {
				t.Errorf("MatchEndpoint() found = %v, expectFound = %v", found, tt.expectFound)
			}
		})
	}
}

func TestAIRegistryRegisterMultiple(t *testing.T) {
	registry := NewAIRegistry()

	providers := []AIProviderConfig{
		{
			Type:      "openai",
			Name:      "OpenAI",
			Hostnames: []string{"api.openai.com"},
		},
		{
			Type:      "anthropic",
			Name:      "Anthropic",
			Hostnames: []string{"api.anthropic.com"},
		},
	}

	err := registry.RegisterMultiple(providers)
	if err != nil {
		t.Fatalf("RegisterMultiple() failed: %v", err)
	}

	all := registry.GetAll()
	if len(all) != 2 {
		t.Errorf("GetAll() returned %d providers, expected 2", len(all))
	}
}

func TestAIRegistryClear(t *testing.T) {
	registry := NewAIRegistry()
	registry.Register(&AIProviderConfig{Type: "openai"})

	if len(registry.GetAll()) == 0 {
		t.Fatal("Register() failed")
	}

	registry.Clear()
	if len(registry.GetAll()) != 0 {
		t.Fatal("Clear() failed to remove all providers")
	}
}

func TestAIRegistryGetNonexistent(t *testing.T) {
	registry := NewAIRegistry()

	provider, ok := registry.Get("nonexistent")
	if ok {
		t.Error("Get() should return false for nonexistent provider")
	}
	if provider != nil {
		t.Error("Get() should return nil provider for nonexistent")
	}
}

func TestMatchWildcard(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		pattern string
		expect  bool
	}{
		{
			name:    "exact match",
			host:    "api.openai.com",
			pattern: "api.openai.com",
			expect:  true,
		},
		{
			name:    "wildcard prefix",
			host:    "chat.openai.com",
			pattern: "*.openai.com",
			expect:  true,
		},
		{
			name:    "wildcard no match",
			host:    "chat.anthropic.com",
			pattern: "*.openai.com",
			expect:  false,
		},
		{
			name:    "case insensitive",
			host:    "API.OPENAI.COM",
			pattern: "*.openai.com",
			expect:  true,
		},
		{
			name:    "with port",
			host:    "chat.openai.com:443",
			pattern: "*.openai.com",
			expect:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchWildcard(tt.host, tt.pattern)
			if result != tt.expect {
				t.Errorf("matchWildcard() = %v, expect = %v", result, tt.expect)
			}
		})
	}
}
