package builtin

import (
	"context"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestBudgetGateDetector(t *testing.T) {
	d := &BudgetGateDetector{}

	tests := []struct {
		name      string
		content   string
		config    map[string]any
		triggered bool
	}{
		{
			name:      "within budget",
			content:   `{"estimated_tokens": 100, "used_tokens": 200}`,
			config:    map[string]any{"max_budget": 1000},
			triggered: false,
		},
		{
			name:      "exceeds budget",
			content:   `{"estimated_tokens": 500, "used_tokens": 600}`,
			config:    map[string]any{"max_budget": 1000},
			triggered: true,
		},
		{
			name:      "at warning threshold",
			content:   `{"estimated_tokens": 100, "used_tokens": 800}`,
			config:    map[string]any{"max_budget": 1000, "warn_threshold": 0.8},
			triggered: true,
		},
		{
			name:      "no budget configured",
			content:   `{"estimated_tokens": 999999}`,
			config:    map[string]any{},
			triggered: false,
		},
		{
			name:      "non-JSON content estimated from words",
			content:   "just some text here for estimation",
			config:    map[string]any{"max_budget": 1},
			triggered: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &policy.GuardrailConfig{
				ID:     "test-budget",
				Name:   "Budget Gate",
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
