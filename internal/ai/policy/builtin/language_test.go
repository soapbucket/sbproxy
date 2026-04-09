package builtin

import (
	"context"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestLanguageDetector(t *testing.T) {
	d := &LanguageDetector{}

	tests := []struct {
		name      string
		content   string
		config    map[string]any
		triggered bool
	}{
		{
			name:      "english allowed",
			content:   "The quick brown fox jumps over the lazy dog and the cat was sitting on the mat in the house",
			config:    map[string]any{"allowed": []any{"en"}, "min_confidence": 0.1},
			triggered: false,
		},
		{
			name:      "english blocked",
			content:   "The quick brown fox jumps over the lazy dog and the cat was sitting on the mat in the house",
			config:    map[string]any{"blocked": []any{"en"}, "min_confidence": 0.1},
			triggered: true,
		},
		{
			name:      "no constraints passes",
			content:   "Any text at all should pass with no constraints configured",
			config:    map[string]any{},
			triggered: false,
		},
		{
			name:      "low confidence skips check",
			content:   "ab",
			config:    map[string]any{"allowed": []any{"en"}, "min_confidence": 0.9},
			triggered: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &policy.GuardrailConfig{
				ID:     "test-lang",
				Name:   "Language Detector",
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

func TestDetectLanguage(t *testing.T) {
	lang, confidence := detectLanguage("The quick brown fox jumps over the lazy dog and the cat was sitting on the mat")
	if lang != "en" {
		t.Errorf("expected en, got %s (confidence: %.2f)", lang, confidence)
	}
	if confidence <= 0 {
		t.Error("expected positive confidence")
	}
}
