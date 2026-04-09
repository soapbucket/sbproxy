package builtin

import (
	"context"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestRegexDetector(t *testing.T) {
	d := NewRegexDetector()

	tests := []struct {
		name      string
		content   string
		config    map[string]any
		triggered bool
		wantErr   bool
	}{
		{
			name:      "pattern matches",
			content:   "Error code: ERR-12345",
			config:    map[string]any{"patterns": []any{`ERR-\d+`}},
			triggered: true,
		},
		{
			name:      "pattern does not match",
			content:   "Everything is fine",
			config:    map[string]any{"patterns": []any{`ERR-\d+`}},
			triggered: false,
		},
		{
			name:      "multiple patterns one match",
			content:   "Warning: timeout occurred",
			config:    map[string]any{"patterns": []any{`ERR-\d+`, `(?i)warning`}},
			triggered: true,
		},
		{
			name:    "invalid regex returns error",
			content: "test",
			config:  map[string]any{"patterns": []any{`[invalid`}},
			wantErr: true,
		},
		{
			name:      "no patterns configured",
			content:   "test",
			config:    map[string]any{},
			triggered: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &policy.GuardrailConfig{
				ID:     "test-regex",
				Name:   "Regex Scanner",
				Action: policy.GuardrailActionBlock,
				Config: tt.config,
			}
			result, err := d.Detect(context.Background(), cfg, tt.content)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Triggered != tt.triggered {
				t.Errorf("triggered = %v, want %v", result.Triggered, tt.triggered)
			}
		})
	}
}
