package builtin

import (
	"context"
	"strings"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestGibberishDetector(t *testing.T) {
	d := &GibberishDetector{}

	tests := []struct {
		name      string
		content   string
		config    map[string]any
		triggered bool
	}{
		{
			name:      "normal text passes",
			content:   "The quick brown fox jumps over the lazy dog near the river bank.",
			config:    nil,
			triggered: false,
		},
		{
			name:      "repeated characters",
			content:   strings.Repeat("aaaa", 20),
			config:    map[string]any{"max_repeated_ratio": 0.5},
			triggered: true,
		},
		{
			name:      "low alphabetic ratio",
			content:   "123!@#$%^&*()456789{}[]|;:',.<>?/`~" + strings.Repeat("0", 40),
			config:    map[string]any{"min_alpha_ratio": 0.3},
			triggered: true,
		},
		{
			name:      "too short to analyze",
			content:   "Hi",
			config:    map[string]any{"min_length": 20},
			triggered: false,
		},
		{
			name:      "very low entropy (repetitive)",
			content:   strings.Repeat("ab", 50),
			config:    map[string]any{"min_entropy": 2.0},
			triggered: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &policy.GuardrailConfig{
				ID:     "test-gibberish",
				Name:   "Gibberish Detector",
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

func TestRepeatedCharRatio(t *testing.T) {
	tests := []struct {
		input string
		want  float64
	}{
		{"abcd", 0.0},
		{"aaaa", 1.0},
		{"aabb", 2.0 / 3.0},
	}
	for _, tt := range tests {
		got := repeatedCharRatio(tt.input)
		if got < tt.want-0.01 || got > tt.want+0.01 {
			t.Errorf("repeatedCharRatio(%q) = %.2f, want %.2f", tt.input, got, tt.want)
		}
	}
}
