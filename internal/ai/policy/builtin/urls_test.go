package builtin

import (
	"context"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestURLDetector(t *testing.T) {
	d := &URLDetector{}

	tests := []struct {
		name      string
		content   string
		config    map[string]any
		triggered bool
	}{
		{
			name:      "blocked domain",
			content:   "Visit https://malware.example.com/payload",
			config:    map[string]any{"blocked_domains": []any{"malware.example.com"}},
			triggered: true,
		},
		{
			name:      "parent domain blocked",
			content:   "Visit https://sub.evil.com/page",
			config:    map[string]any{"blocked_domains": []any{"evil.com"}},
			triggered: true,
		},
		{
			name:      "safe domain",
			content:   "Visit https://google.com/search",
			config:    map[string]any{"blocked_domains": []any{"evil.com"}},
			triggered: false,
		},
		{
			name:      "require https - http rejected",
			content:   "Visit http://example.com",
			config:    map[string]any{"require_https": true},
			triggered: true,
		},
		{
			name:      "require https - https passes",
			content:   "Visit https://example.com",
			config:    map[string]any{"require_https": true},
			triggered: false,
		},
		{
			name:      "detect mode finds URLs",
			content:   "Check https://example.com and http://test.com",
			config:    map[string]any{"mode": "detect"},
			triggered: true,
		},
		{
			name:      "detect mode no URLs",
			content:   "No URLs here at all",
			config:    map[string]any{"mode": "detect"},
			triggered: false,
		},
		{
			name:      "no URLs in content",
			content:   "Plain text with no links",
			config:    map[string]any{"blocked_domains": []any{"evil.com"}},
			triggered: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &policy.GuardrailConfig{
				ID:     "test-url",
				Name:   "URL Validator",
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
