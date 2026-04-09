package builtin

import (
	"context"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestRequestTypeDetector(t *testing.T) {
	d := &RequestTypeDetector{}

	tests := []struct {
		name      string
		content   string
		config    map[string]any
		triggered bool
	}{
		{
			name:      "allowed type passes",
			content:   "chat",
			config:    map[string]any{"allowed": []any{"chat", "completion"}},
			triggered: false,
		},
		{
			name:      "not in allowed list",
			content:   "image",
			config:    map[string]any{"allowed": []any{"chat", "completion"}},
			triggered: true,
		},
		{
			name:      "blocked type triggers",
			content:   "image",
			config:    map[string]any{"blocked": []any{"image"}},
			triggered: true,
		},
		{
			name:      "no constraints",
			content:   "anything",
			config:    map[string]any{},
			triggered: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &policy.GuardrailConfig{
				ID:     "test-reqtype",
				Name:   "Request Type",
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
