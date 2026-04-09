package builtin

import (
	"context"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestToolCallDetector(t *testing.T) {
	d := &ToolCallDetector{}

	tests := []struct {
		name      string
		content   string
		config    map[string]any
		triggered bool
	}{
		{
			name:      "within max calls",
			content:   `[{"name": "search"}, {"name": "calc"}]`,
			config:    map[string]any{"max_calls": 5},
			triggered: false,
		},
		{
			name:      "exceeds max calls",
			content:   `[{"name": "a"}, {"name": "b"}, {"name": "c"}]`,
			config:    map[string]any{"max_calls": 2},
			triggered: true,
		},
		{
			name:      "blocked tool",
			content:   `[{"name": "shell_exec"}]`,
			config:    map[string]any{"blocked_tools": []any{"shell_exec"}},
			triggered: true,
		},
		{
			name:      "allowed tool list",
			content:   `[{"name": "search"}]`,
			config:    map[string]any{"allowed_tools": []any{"search", "calc"}},
			triggered: false,
		},
		{
			name:      "tool not in allowed list",
			content:   `[{"name": "shell_exec"}]`,
			config:    map[string]any{"allowed_tools": []any{"search", "calc"}},
			triggered: true,
		},
		{
			name:      "nested function name format",
			content:   `[{"function": {"name": "search"}}]`,
			config:    map[string]any{"max_calls": 5},
			triggered: false,
		},
		{
			name:      "tool_calls field format",
			content:   `{"tool_calls": [{"name": "search"}, {"name": "calc"}]}`,
			config:    map[string]any{"max_calls": 1},
			triggered: true,
		},
		{
			name:      "no tool calls",
			content:   "plain text, not json",
			config:    map[string]any{"max_calls": 0},
			triggered: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &policy.GuardrailConfig{
				ID:     "test-tools",
				Name:   "Tool Limiter",
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
