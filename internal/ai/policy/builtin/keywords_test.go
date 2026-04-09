package builtin

import (
	"context"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestKeywordDetector(t *testing.T) {
	d := &KeywordDetector{}

	tests := []struct {
		name      string
		content   string
		config    map[string]any
		triggered bool
	}{
		{
			name:      "exact match found",
			content:   "This contains a bad word",
			config:    map[string]any{"keywords": []any{"bad word"}},
			triggered: true,
		},
		{
			name:      "case insensitive match",
			content:   "This contains BAD WORD",
			config:    map[string]any{"keywords": []any{"bad word"}},
			triggered: true,
		},
		{
			name:      "case sensitive no match",
			content:   "This contains BAD WORD",
			config:    map[string]any{"keywords": []any{"bad word"}, "case_sensitive": true},
			triggered: false,
		},
		{
			name:      "glob mode match",
			content:   "The secret_key_value is here",
			config:    map[string]any{"keywords": []any{"secret*"}, "mode": "glob"},
			triggered: true,
		},
		{
			name:      "glob mode no match",
			content:   "Nothing here at all",
			config:    map[string]any{"keywords": []any{"secret*"}, "mode": "glob"},
			triggered: false,
		},
		{
			name:      "no keywords configured",
			content:   "Anything goes",
			config:    map[string]any{},
			triggered: false,
		},
		{
			name:      "empty content",
			content:   "",
			config:    map[string]any{"keywords": []any{"test"}},
			triggered: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &policy.GuardrailConfig{
				ID:     "test-kw",
				Name:   "Keyword Blocklist",
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
