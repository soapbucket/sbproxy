package builtin

import (
	"context"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestSecretDetector(t *testing.T) {
	d := &SecretDetector{}

	tests := []struct {
		name      string
		content   string
		config    map[string]any
		triggered bool
	}{
		{
			name:      "AWS access key detected",
			content:   "Here is my key: AKIAIOSFODNN7EXAMPLE",
			config:    nil,
			triggered: true,
		},
		{
			name:      "GitHub token detected",
			content:   "Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			config:    nil,
			triggered: true,
		},
		{
			name:      "Stripe key detected",
			content:   "sk_test_ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			config:    nil,
			triggered: true,
		},
		{
			name:      "private key header detected",
			content:   "-----BEGIN RSA PRIVATE KEY-----",
			config:    nil,
			triggered: true,
		},
		{
			name:      "high entropy string",
			content:   "Token: aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2u",
			config:    map[string]any{"types": []any{"high_entropy"}, "entropy_threshold": 3.5, "entropy_min_length": 10},
			triggered: true,
		},
		{
			name:      "no secrets in clean text",
			content:   "This is a normal sentence with no secrets or keys.",
			config:    nil,
			triggered: false,
		},
		{
			name:      "filtered types - only aws",
			content:   "AKIAIOSFODNN7EXAMPLE and ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			config:    map[string]any{"types": []any{"aws_access_key"}},
			triggered: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &policy.GuardrailConfig{
				ID:     "test-secret",
				Name:   "Secret Detector",
				Action: policy.GuardrailActionBlock,
				Config: tt.config,
			}
			result, err := d.Detect(context.Background(), cfg, tt.content)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Triggered != tt.triggered {
				t.Errorf("triggered = %v, want %v (details: %s)", result.Triggered, tt.triggered, result.Details)
			}
		})
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		input   string
		minEntr float64
	}{
		{"aaaa", 0.0},
		{"abcd", 2.0},
		{"aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2u", 4.0},
	}
	for _, tt := range tests {
		e := shannonEntropy(tt.input)
		if e < tt.minEntr {
			t.Errorf("shannonEntropy(%q) = %.2f, want >= %.2f", tt.input, e, tt.minEntr)
		}
	}
}
