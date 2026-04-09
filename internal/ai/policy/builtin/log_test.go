package builtin

import (
	"context"
	"strings"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestLogDetector(t *testing.T) {
	d := &LogDetector{}

	tests := []struct {
		name         string
		content      string
		config       map[string]any
		triggered    bool
		hasPreview   bool
		truncated    bool
	}{
		{
			name:       "short content logged",
			content:    "Hello world",
			config:     nil,
			triggered:  false,
			hasPreview: true,
		},
		{
			name:       "long content truncated",
			content:    strings.Repeat("a", 500),
			config:     map[string]any{"max_preview": 100},
			triggered:  false,
			hasPreview: true,
			truncated:  true,
		},
		{
			name:       "stats disabled",
			content:    "test content",
			config:     map[string]any{"include_stats": false},
			triggered:  false,
			hasPreview: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &policy.GuardrailConfig{
				ID:     "test-log",
				Name:   "Audit Log",
				Action: policy.GuardrailActionLog,
				Config: tt.config,
			}
			result, err := d.Detect(context.Background(), cfg, tt.content)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Triggered != tt.triggered {
				t.Errorf("triggered = %v, want %v", result.Triggered, tt.triggered)
			}
			if tt.hasPreview && result.Details == "" {
				t.Error("expected details with preview")
			}
			if tt.truncated && !strings.Contains(result.Details, "...") {
				t.Error("expected truncated preview with '...'")
			}
		})
	}
}
