package builtin

import (
	"context"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestCodeDetector(t *testing.T) {
	d := &CodeDetector{}

	tests := []struct {
		name      string
		content   string
		config    map[string]any
		triggered bool
	}{
		{
			name:      "SQL detected",
			content:   "SELECT * FROM users WHERE id = 1",
			config:    nil,
			triggered: true,
		},
		{
			name:      "Python detected",
			content:   "def hello_world():\n    print('hello')",
			config:    nil,
			triggered: true,
		},
		{
			name:      "JavaScript detected",
			content:   "const x = 42;\nconsole.log(x);",
			config:    nil,
			triggered: true,
		},
		{
			name:      "Go detected",
			content:   "package main\nfunc main() {\n}",
			config:    nil,
			triggered: true,
		},
		{
			name:      "shell detected",
			content:   "sudo apt-get install nginx",
			config:    nil,
			triggered: true,
		},
		{
			name:      "no code in plain text",
			content:   "This is a regular sentence about going to the store.",
			config:    nil,
			triggered: false,
		},
		{
			name:      "filtered languages - only SQL",
			content:   "const x = 42; SELECT * FROM users WHERE id = 1",
			config:    map[string]any{"languages": []any{"sql"}},
			triggered: true,
		},
		{
			name:      "require mode - no code triggers",
			content:   "Just plain text here",
			config:    map[string]any{"mode": "require"},
			triggered: true,
		},
		{
			name:      "require mode - has code passes",
			content:   "SELECT * FROM users WHERE id = 1",
			config:    map[string]any{"mode": "require"},
			triggered: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &policy.GuardrailConfig{
				ID:     "test-code",
				Name:   "Code Detector",
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
