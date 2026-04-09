package builtin

import (
	"context"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestLengthDetector(t *testing.T) {
	d := &LengthDetector{}

	tests := []struct {
		name      string
		content   string
		config    map[string]any
		triggered bool
	}{
		{
			name:      "within bounds",
			content:   "Hello world",
			config:    map[string]any{"min_chars": 5, "max_chars": 100},
			triggered: false,
		},
		{
			name:      "exceeds max chars",
			content:   "Hello world",
			config:    map[string]any{"max_chars": 5},
			triggered: true,
		},
		{
			name:      "below min chars",
			content:   "Hi",
			config:    map[string]any{"min_chars": 10},
			triggered: true,
		},
		{
			name:      "exceeds max words",
			content:   "one two three four five",
			config:    map[string]any{"max_words": 3},
			triggered: true,
		},
		{
			name:      "sentence count check",
			content:   "First sentence. Second sentence. Third sentence.",
			config:    map[string]any{"max_sentences": 2},
			triggered: true,
		},
		{
			name:      "no constraints",
			content:   "Anything goes here",
			config:    map[string]any{},
			triggered: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &policy.GuardrailConfig{
				ID:     "test-length",
				Name:   "Length Check",
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

func TestCountSentences(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"Hello.", 1},
		{"Hello. World.", 2},
		{"What? Really! Yes.", 3},
		{"No punctuation here", 1},
		{"", 0},
	}
	for _, tt := range tests {
		if got := countSentences(tt.input); got != tt.want {
			t.Errorf("countSentences(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}
