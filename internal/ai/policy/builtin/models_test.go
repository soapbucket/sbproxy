package builtin

import (
	"context"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestModelDetector(t *testing.T) {
	d := &ModelDetector{}

	tests := []struct {
		name      string
		content   string
		config    map[string]any
		triggered bool
	}{
		{
			name:      "allowed model passes",
			content:   "gpt-4",
			config:    map[string]any{"allowed": []any{"gpt-4", "gpt-3.5-turbo"}},
			triggered: false,
		},
		{
			name:      "not in allowed list",
			content:   "claude-3",
			config:    map[string]any{"allowed": []any{"gpt-4", "gpt-3.5-turbo"}},
			triggered: true,
		},
		{
			name:      "blocked model triggers",
			content:   "gpt-4",
			config:    map[string]any{"blocked": []any{"gpt-4"}},
			triggered: true,
		},
		{
			name:      "prefix match allowed",
			content:   "gpt-4-turbo-preview",
			config:    map[string]any{"allowed": []any{"gpt-4"}, "prefix_match": true},
			triggered: false,
		},
		{
			name:      "prefix match blocked",
			content:   "gpt-4-turbo",
			config:    map[string]any{"blocked": []any{"gpt-4"}, "prefix_match": true},
			triggered: true,
		},
		{
			name:      "no constraints",
			content:   "any-model",
			config:    map[string]any{},
			triggered: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &policy.GuardrailConfig{
				ID:     "test-model",
				Name:   "Model Check",
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
