package builtin

import (
	"context"
	"strings"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestTokenEstimatorDetector(t *testing.T) {
	d := &TokenEstimatorDetector{}

	tests := []struct {
		name      string
		content   string
		config    map[string]any
		triggered bool
	}{
		{
			name:      "within token limit",
			content:   "Hello world",
			config:    map[string]any{"max_tokens": 100},
			triggered: false,
		},
		{
			name:      "exceeds token limit",
			content:   strings.Repeat("word ", 100),
			config:    map[string]any{"max_tokens": 10},
			triggered: true,
		},
		{
			name:      "below minimum tokens",
			content:   "Hi",
			config:    map[string]any{"min_tokens": 10},
			triggered: true,
		},
		{
			name:      "custom ratio",
			content:   "one two three four five",
			config:    map[string]any{"max_tokens": 5, "ratio": 1.0},
			triggered: false,
		},
		{
			name:      "no limits",
			content:   strings.Repeat("word ", 1000),
			config:    map[string]any{},
			triggered: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &policy.GuardrailConfig{
				ID:     "test-tokens",
				Name:   "Token Estimator",
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
