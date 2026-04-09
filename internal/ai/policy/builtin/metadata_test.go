package builtin

import (
	"context"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestMetadataDetector(t *testing.T) {
	d := &MetadataDetector{}

	tests := []struct {
		name      string
		content   string
		config    map[string]any
		triggered bool
	}{
		{
			name:      "required keys present",
			content:   `{"user_id": "abc", "session_id": "xyz"}`,
			config:    map[string]any{"required_keys": []any{"user_id", "session_id"}},
			triggered: false,
		},
		{
			name:      "required key missing",
			content:   `{"user_id": "abc"}`,
			config:    map[string]any{"required_keys": []any{"user_id", "session_id"}},
			triggered: true,
		},
		{
			name:    "required value matches",
			content: `{"env": "production"}`,
			config: map[string]any{
				"required_values": map[string]any{"env": "production"},
			},
			triggered: false,
		},
		{
			name:    "required value mismatch",
			content: `{"env": "staging"}`,
			config: map[string]any{
				"required_values": map[string]any{"env": "production"},
			},
			triggered: true,
		},
		{
			name:      "non-JSON content with required keys",
			content:   "not json",
			config:    map[string]any{"required_keys": []any{"user_id"}},
			triggered: true,
		},
		{
			name:      "no requirements",
			content:   `{"anything": true}`,
			config:    map[string]any{},
			triggered: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &policy.GuardrailConfig{
				ID:     "test-metadata",
				Name:   "Metadata Check",
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
