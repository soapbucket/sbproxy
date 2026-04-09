package builtin

import (
	"context"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestPIIDetector(t *testing.T) {
	d := &PIIDetector{}

	tests := []struct {
		name      string
		content   string
		config    map[string]any
		triggered bool
		details   string
	}{
		{
			name:      "email detected",
			content:   "Contact me at user@example.com for more info",
			config:    nil,
			triggered: true,
			details:   "detected PII types: email",
		},
		{
			name:      "phone detected",
			content:   "Call me at 555-123-4567",
			config:    nil,
			triggered: true,
			details:   "detected PII types: phone",
		},
		{
			name:      "SSN detected",
			content:   "My SSN is 123-45-6789",
			config:    nil,
			triggered: true,
			details:   "detected PII types: ssn",
		},
		{
			name:      "credit card with Luhn",
			content:   "Card number: 4111111111111111",
			config:    map[string]any{"types": []any{"credit_card"}},
			triggered: true,
			details:   "detected PII types: credit_card",
		},
		{
			name:      "invalid credit card fails Luhn",
			content:   "Card number: 4111111111111112",
			config:    map[string]any{"types": []any{"credit_card"}},
			triggered: false,
		},
		{
			name:      "IP address detected",
			content:   "Server at 192.168.1.100",
			config:    nil,
			triggered: true,
			details:   "detected PII types: ip_address",
		},
		{
			name:      "no PII in clean text",
			content:   "This is a perfectly normal sentence with no personal data.",
			config:    nil,
			triggered: false,
		},
		{
			name:      "filtered types - only email",
			content:   "Email: user@test.com and SSN: 123-45-6789",
			config:    map[string]any{"types": []any{"email"}},
			triggered: true,
			details:   "detected PII types: email",
		},
		{
			name:      "multiple PII types",
			content:   "Email: a@b.com, Phone: 555-123-4567, SSN: 123-45-6789",
			config:    nil,
			triggered: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &policy.GuardrailConfig{
				ID:     "test-pii",
				Name:   "PII Scanner",
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
			if tt.details != "" && result.Details != tt.details {
				t.Errorf("details = %q, want %q", result.Details, tt.details)
			}
		})
	}
}

func TestLuhnCheck(t *testing.T) {
	tests := []struct {
		digits string
		valid  bool
	}{
		{"4111111111111111", true},  // Visa test card.
		{"5500000000000004", true},  // Mastercard test card.
		{"4111111111111112", false}, // Invalid.
		{"123", false},             // Too short.
	}
	for _, tt := range tests {
		if got := luhnCheck(tt.digits); got != tt.valid {
			t.Errorf("luhnCheck(%q) = %v, want %v", tt.digits, got, tt.valid)
		}
	}
}
