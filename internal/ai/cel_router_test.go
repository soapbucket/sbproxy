package ai

import (
	"context"
	"testing"

	"github.com/soapbucket/sbproxy/internal/extension/cel"
)

func TestCELRouter_ModelMatch(t *testing.T) {
	router, err := NewCELRouter(&CELRoutingConfig{
		Rules: []CELRoutingRule{
			{
				Name:       "gpt4-to-openai",
				Expression: `ai.model.startsWith("gpt-4")`,
				Provider:   "openai",
			},
			{
				Name:       "claude-to-anthropic",
				Expression: `ai.model.startsWith("claude")`,
				Provider:   "anthropic",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewCELRouter() error: %v", err)
	}

	tests := []struct {
		name         string
		model        string
		wantProvider string
		wantMatched  bool
	}{
		{"gpt-4 match", "gpt-4-turbo", "openai", true},
		{"claude match", "claude-3-opus", "anthropic", true},
		{"no match", "llama-3", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &ChatCompletionRequest{Model: tt.model}
			vars := &cel.AIContextVars{Model: tt.model}
			provider, _, matched := router.Evaluate(context.Background(), req, vars)
			if matched != tt.wantMatched {
				t.Errorf("matched = %v, want %v", matched, tt.wantMatched)
			}
			if provider != tt.wantProvider {
				t.Errorf("provider = %q, want %q", provider, tt.wantProvider)
			}
		})
	}
}

func TestCELRouter_BudgetMatch(t *testing.T) {
	router, err := NewCELRouter(&CELRoutingConfig{
		Rules: []CELRoutingRule{
			{
				Name:       "over-budget",
				Expression: `budget.utilization > 0.8`,
				Provider:   "cheap-provider",
			},
		},
		FallbackProvider: "default-provider",
	})
	if err != nil {
		t.Fatalf("NewCELRouter() error: %v", err)
	}

	tests := []struct {
		name         string
		utilization  float64
		wantProvider string
		wantMatched  bool
	}{
		{"over budget", 0.9, "cheap-provider", true},
		{"at threshold", 0.8, "default-provider", false},
		{"under budget", 0.5, "default-provider", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &ChatCompletionRequest{Model: "gpt-4"}
			vars := &cel.AIContextVars{
				Model: "gpt-4",
				Budget: map[string]any{
					"utilization":      tt.utilization,
					"remaining_tokens": int64(10000),
					"period":           "monthly",
				},
			}
			provider, _, matched := router.Evaluate(context.Background(), req, vars)
			if matched != tt.wantMatched {
				t.Errorf("matched = %v, want %v", matched, tt.wantMatched)
			}
			if provider != tt.wantProvider {
				t.Errorf("provider = %q, want %q", provider, tt.wantProvider)
			}
		})
	}
}

func TestCELRouter_ToolsMatch(t *testing.T) {
	router, err := NewCELRouter(&CELRoutingConfig{
		Rules: []CELRoutingRule{
			{
				Name:       "tools-streaming",
				Expression: `ai.has_tools && ai.is_streaming`,
				Provider:   "tool-streaming-provider",
			},
			{
				Name:       "tools-only",
				Expression: `ai.has_tools == true`,
				Provider:   "tool-provider",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewCELRouter() error: %v", err)
	}

	tests := []struct {
		name         string
		hasTools     bool
		isStreaming  bool
		wantProvider string
		wantMatched  bool
	}{
		{"tools + streaming", true, true, "tool-streaming-provider", true},
		{"tools only", true, false, "tool-provider", true},
		{"streaming only", false, true, "", false},
		{"neither", false, false, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &ChatCompletionRequest{Model: "gpt-4"}
			vars := &cel.AIContextVars{
				Model:       "gpt-4",
				HasTools:    tt.hasTools,
				IsStreaming: tt.isStreaming,
			}
			provider, _, matched := router.Evaluate(context.Background(), req, vars)
			if matched != tt.wantMatched {
				t.Errorf("matched = %v, want %v", matched, tt.wantMatched)
			}
			if provider != tt.wantProvider {
				t.Errorf("provider = %q, want %q", provider, tt.wantProvider)
			}
		})
	}
}

func TestCELRouter_Priority(t *testing.T) {
	router, err := NewCELRouter(&CELRoutingConfig{
		Rules: []CELRoutingRule{
			{
				Name:       "low-priority",
				Expression: `ai.model == "gpt-4"`,
				Provider:   "provider-b",
				Priority:   10,
			},
			{
				Name:       "high-priority",
				Expression: `ai.model == "gpt-4"`,
				Provider:   "provider-a",
				Priority:   1,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewCELRouter() error: %v", err)
	}

	req := &ChatCompletionRequest{Model: "gpt-4"}
	vars := &cel.AIContextVars{Model: "gpt-4"}
	provider, _, matched := router.Evaluate(context.Background(), req, vars)
	if !matched {
		t.Fatal("expected a match")
	}
	if provider != "provider-a" {
		t.Errorf("provider = %q, want provider-a (higher priority)", provider)
	}
}

func TestCELRouter_NoMatch(t *testing.T) {
	router, err := NewCELRouter(&CELRoutingConfig{
		Rules: []CELRoutingRule{
			{
				Name:       "specific",
				Expression: `ai.model == "gpt-4"`,
				Provider:   "openai",
			},
		},
		FallbackProvider: "fallback-provider",
	})
	if err != nil {
		t.Fatalf("NewCELRouter() error: %v", err)
	}

	req := &ChatCompletionRequest{Model: "claude-3"}
	vars := &cel.AIContextVars{Model: "claude-3"}
	provider, _, matched := router.Evaluate(context.Background(), req, vars)
	if matched {
		t.Error("expected no match")
	}
	if provider != "fallback-provider" {
		t.Errorf("provider = %q, want fallback-provider", provider)
	}
}

func TestCELRouter_InvalidExpression(t *testing.T) {
	_, err := NewCELRouter(&CELRoutingConfig{
		Rules: []CELRoutingRule{
			{
				Name:       "bad-expr",
				Expression: `this is not valid CEL!!!`,
				Provider:   "openai",
			},
		},
	})
	if err == nil {
		t.Error("expected error for invalid CEL expression")
	}
}

func TestCELRouter_EmptyExpression(t *testing.T) {
	_, err := NewCELRouter(&CELRoutingConfig{
		Rules: []CELRoutingRule{
			{
				Name:       "empty",
				Expression: "",
				Provider:   "openai",
			},
		},
	})
	if err == nil {
		t.Error("expected error for empty expression")
	}
}

func TestCELRouter_EmptyProvider(t *testing.T) {
	_, err := NewCELRouter(&CELRoutingConfig{
		Rules: []CELRoutingRule{
			{
				Name:       "no-provider",
				Expression: `ai.model == "gpt-4"`,
				Provider:   "",
			},
		},
	})
	if err == nil {
		t.Error("expected error for empty provider")
	}
}

func TestCELRouter_NonBoolExpression(t *testing.T) {
	_, err := NewCELRouter(&CELRoutingConfig{
		Rules: []CELRoutingRule{
			{
				Name:       "returns-string",
				Expression: `ai.model`,
				Provider:   "openai",
			},
		},
	})
	if err == nil {
		t.Error("expected error for non-bool expression")
	}
}

func TestCELRouter_MultipleRules(t *testing.T) {
	// Both rules match, but first match (by priority) wins
	router, err := NewCELRouter(&CELRoutingConfig{
		Rules: []CELRoutingRule{
			{
				Name:       "first",
				Expression: `ai.message_count > 0`,
				Provider:   "provider-first",
				Priority:   0,
			},
			{
				Name:       "second",
				Expression: `ai.message_count > 0`,
				Provider:   "provider-second",
				Priority:   1,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewCELRouter() error: %v", err)
	}

	req := &ChatCompletionRequest{Model: "gpt-4"}
	vars := &cel.AIContextVars{Model: "gpt-4", MessageCount: 5}
	provider, _, matched := router.Evaluate(context.Background(), req, vars)
	if !matched {
		t.Fatal("expected a match")
	}
	if provider != "provider-first" {
		t.Errorf("provider = %q, want provider-first (first match wins)", provider)
	}
}

func TestCELRouter_ModelOverride(t *testing.T) {
	router, err := NewCELRouter(&CELRoutingConfig{
		Rules: []CELRoutingRule{
			{
				Name:       "downgrade",
				Expression: `budget.utilization > 0.9`,
				Provider:   "openai",
				Model:      "gpt-3.5-turbo",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewCELRouter() error: %v", err)
	}

	req := &ChatCompletionRequest{Model: "gpt-4"}
	vars := &cel.AIContextVars{
		Model: "gpt-4",
		Budget: map[string]any{
			"utilization":      0.95,
			"remaining_tokens": int64(500),
			"period":           "monthly",
		},
	}
	provider, model, matched := router.Evaluate(context.Background(), req, vars)
	if !matched {
		t.Fatal("expected a match")
	}
	if provider != "openai" {
		t.Errorf("provider = %q, want openai", provider)
	}
	if model != "gpt-3.5-turbo" {
		t.Errorf("model = %q, want gpt-3.5-turbo", model)
	}
}

func TestCELRouter_NilRequest(t *testing.T) {
	router, err := NewCELRouter(&CELRoutingConfig{
		Rules: []CELRoutingRule{
			{
				Name:       "any",
				Expression: `ai.model == "gpt-4"`,
				Provider:   "openai",
			},
		},
		FallbackProvider: "fallback",
	})
	if err != nil {
		t.Fatalf("NewCELRouter() error: %v", err)
	}

	provider, _, matched := router.Evaluate(context.Background(), nil, nil)
	if matched {
		t.Error("expected no match for nil request")
	}
	if provider != "fallback" {
		t.Errorf("provider = %q, want fallback", provider)
	}
}

func TestCELRouter_NilConfig(t *testing.T) {
	_, err := NewCELRouter(nil)
	if err == nil {
		t.Error("expected error for nil config")
	}
}

func TestCELRouter_CancelledContext(t *testing.T) {
	router, err := NewCELRouter(&CELRoutingConfig{
		Rules: []CELRoutingRule{
			{
				Name:       "match-all",
				Expression: `ai.model != ""`,
				Provider:   "openai",
			},
		},
		FallbackProvider: "fallback",
	})
	if err != nil {
		t.Fatalf("NewCELRouter() error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req := &ChatCompletionRequest{Model: "gpt-4"}
	vars := &cel.AIContextVars{Model: "gpt-4"}
	provider, _, matched := router.Evaluate(ctx, req, vars)
	if matched {
		t.Error("expected no match for cancelled context")
	}
	if provider != "fallback" {
		t.Errorf("provider = %q, want fallback", provider)
	}
}

func TestCELRouter_RuleCount(t *testing.T) {
	router, err := NewCELRouter(&CELRoutingConfig{
		Rules: []CELRoutingRule{
			{Name: "r1", Expression: `ai.model == "a"`, Provider: "p1"},
			{Name: "r2", Expression: `ai.model == "b"`, Provider: "p2"},
			{Name: "r3", Expression: `ai.model == "c"`, Provider: "p3"},
		},
	})
	if err != nil {
		t.Fatalf("NewCELRouter() error: %v", err)
	}
	if router.RuleCount() != 3 {
		t.Errorf("RuleCount() = %d, want 3", router.RuleCount())
	}
}
