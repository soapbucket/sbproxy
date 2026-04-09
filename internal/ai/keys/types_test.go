package keys

import (
	"testing"
	"time"
)

func TestVirtualKey_IsActive(t *testing.T) {
	tests := []struct {
		name   string
		key    VirtualKey
		expect bool
	}{
		{
			name:   "active key with no expiry",
			key:    VirtualKey{Status: "active"},
			expect: true,
		},
		{
			name:   "revoked key",
			key:    VirtualKey{Status: "revoked"},
			expect: false,
		},
		{
			name:   "expired status",
			key:    VirtualKey{Status: "expired"},
			expect: false,
		},
		{
			name: "active but past expiry",
			key: VirtualKey{
				Status:    "active",
				ExpiresAt: timePtr(time.Now().Add(-1 * time.Hour)),
			},
			expect: false,
		},
		{
			name: "active with future expiry",
			key: VirtualKey{
				Status:    "active",
				ExpiresAt: timePtr(time.Now().Add(24 * time.Hour)),
			},
			expect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.key.IsActive(); got != tt.expect {
				t.Errorf("IsActive() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestVirtualKey_IsModelAllowed(t *testing.T) {
	tests := []struct {
		name   string
		key    VirtualKey
		model  string
		expect bool
	}{
		{
			name:   "no restrictions",
			key:    VirtualKey{},
			model:  "gpt-4",
			expect: true,
		},
		{
			name:   "allowed model present",
			key:    VirtualKey{AllowedModels: []string{"gpt-4", "gpt-3.5-turbo"}},
			model:  "gpt-4",
			expect: true,
		},
		{
			name:   "model not in allowed list",
			key:    VirtualKey{AllowedModels: []string{"gpt-3.5-turbo"}},
			model:  "gpt-4",
			expect: false,
		},
		{
			name:   "model in blocked list",
			key:    VirtualKey{BlockedModels: []string{"gpt-4"}},
			model:  "gpt-4",
			expect: false,
		},
		{
			name:   "blocked takes precedence over allowed",
			key:    VirtualKey{AllowedModels: []string{"gpt-4"}, BlockedModels: []string{"gpt-4"}},
			model:  "gpt-4",
			expect: false,
		},
		{
			name:   "case insensitive match",
			key:    VirtualKey{AllowedModels: []string{"GPT-4"}},
			model:  "gpt-4",
			expect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.key.IsModelAllowed(tt.model); got != tt.expect {
				t.Errorf("IsModelAllowed(%q) = %v, want %v", tt.model, got, tt.expect)
			}
		})
	}
}

func TestVirtualKey_IsProviderAllowed(t *testing.T) {
	tests := []struct {
		name     string
		key      VirtualKey
		provider string
		expect   bool
	}{
		{
			name:     "no restrictions",
			key:      VirtualKey{},
			provider: "openai",
			expect:   true,
		},
		{
			name:     "provider in allowed list",
			key:      VirtualKey{AllowedProviders: []string{"openai", "anthropic"}},
			provider: "openai",
			expect:   true,
		},
		{
			name:     "provider not in allowed list",
			key:      VirtualKey{AllowedProviders: []string{"anthropic"}},
			provider: "openai",
			expect:   false,
		},
		{
			name:     "case insensitive",
			key:      VirtualKey{AllowedProviders: []string{"OpenAI"}},
			provider: "openai",
			expect:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.key.IsProviderAllowed(tt.provider); got != tt.expect {
				t.Errorf("IsProviderAllowed(%q) = %v, want %v", tt.provider, got, tt.expect)
			}
		})
	}
}

func timePtr(t time.Time) *time.Time {
	return &t
}
