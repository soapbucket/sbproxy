package builtin

import (
	"context"
	"strings"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestResponseLengthDetector(t *testing.T) {
	d := &ResponseLengthDetector{}

	tests := []struct {
		name      string
		content   string
		config    map[string]any
		triggered bool
	}{
		{
			name:      "within char limit",
			content:   "Hello",
			config:    map[string]any{"max_chars": 100},
			triggered: false,
		},
		{
			name:      "exceeds char limit",
			content:   strings.Repeat("a", 200),
			config:    map[string]any{"max_chars": 100},
			triggered: true,
		},
		{
			name:      "exceeds word limit",
			content:   strings.Repeat("word ", 50),
			config:    map[string]any{"max_words": 10},
			triggered: true,
		},
		{
			name:      "exceeds line limit",
			content:   strings.Repeat("line\n", 20),
			config:    map[string]any{"max_lines": 5},
			triggered: true,
		},
		{
			name:      "within all limits",
			content:   "Short response",
			config:    map[string]any{"max_chars": 1000, "max_words": 100, "max_lines": 10},
			triggered: false,
		},
		{
			name:      "no limits",
			content:   strings.Repeat("word ", 10000),
			config:    map[string]any{},
			triggered: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &policy.GuardrailConfig{
				ID:     "test-resplen",
				Name:   "Response Length",
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
