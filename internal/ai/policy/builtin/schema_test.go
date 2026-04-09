package builtin

import (
	"context"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestSchemaDetector(t *testing.T) {
	d := &SchemaDetector{}

	tests := []struct {
		name      string
		content   string
		config    map[string]any
		triggered bool
	}{
		{
			name:    "valid object matches schema",
			content: `{"name": "Alice", "age": 30}`,
			config: map[string]any{
				"schema": map[string]any{
					"type":     "object",
					"required": []any{"name", "age"},
					"properties": map[string]any{
						"name": map[string]any{"type": "string"},
						"age":  map[string]any{"type": "number"},
					},
				},
			},
			triggered: false,
		},
		{
			name:    "missing required field",
			content: `{"name": "Alice"}`,
			config: map[string]any{
				"schema": map[string]any{
					"type":     "object",
					"required": []any{"name", "age"},
				},
			},
			triggered: true,
		},
		{
			name:    "wrong type",
			content: `"just a string"`,
			config: map[string]any{
				"schema": map[string]any{"type": "object"},
			},
			triggered: true,
		},
		{
			name:      "invalid JSON",
			content:   `not json at all`,
			config:    map[string]any{"schema": map[string]any{"type": "object"}},
			triggered: true,
		},
		{
			name:    "strict mode rejects unknown props",
			content: `{"name": "Alice", "extra": true}`,
			config: map[string]any{
				"strict": true,
				"schema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"name": map[string]any{"type": "string"},
					},
				},
			},
			triggered: true,
		},
		{
			name:      "no schema configured",
			content:   `{"anything": true}`,
			config:    map[string]any{},
			triggered: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &policy.GuardrailConfig{
				ID:     "test-schema",
				Name:   "Schema Validator",
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
