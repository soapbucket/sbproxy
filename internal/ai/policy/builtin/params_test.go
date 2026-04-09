package builtin

import (
	"context"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestParamsDetector(t *testing.T) {
	d := &ParamsDetector{}

	tests := []struct {
		name      string
		content   string
		config    map[string]any
		triggered bool
	}{
		{
			name:    "within bounds",
			content: `{"temperature": 0.7, "max_tokens": 100}`,
			config: map[string]any{
				"rules": map[string]any{
					"temperature": map[string]any{"min": 0.0, "max": 2.0},
					"max_tokens":  map[string]any{"min": 1.0, "max": 4096.0},
				},
			},
			triggered: false,
		},
		{
			name:    "temperature too high",
			content: `{"temperature": 3.0}`,
			config: map[string]any{
				"rules": map[string]any{
					"temperature": map[string]any{"max": 2.0},
				},
			},
			triggered: true,
		},
		{
			name:    "max_tokens too low",
			content: `{"max_tokens": 0}`,
			config: map[string]any{
				"rules": map[string]any{
					"max_tokens": map[string]any{"min": 1.0},
				},
			},
			triggered: true,
		},
		{
			name:    "allowed values check",
			content: `{"model": "gpt-4"}`,
			config: map[string]any{
				"rules": map[string]any{
					"model": map[string]any{"allowed": []any{"gpt-3.5-turbo", "gpt-4"}},
				},
			},
			triggered: false,
		},
		{
			name:    "value not in allowed list",
			content: `{"model": "claude-3"}`,
			config: map[string]any{
				"rules": map[string]any{
					"model": map[string]any{"allowed": []any{"gpt-3.5-turbo", "gpt-4"}},
				},
			},
			triggered: true,
		},
		{
			name:      "invalid JSON",
			content:   "not json",
			config:    map[string]any{"rules": map[string]any{"temp": map[string]any{"max": 1.0}}},
			triggered: true,
		},
		{
			name:      "no rules configured",
			content:   `{"temperature": 99}`,
			config:    map[string]any{},
			triggered: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &policy.GuardrailConfig{
				ID:     "test-params",
				Name:   "Param Guard",
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
