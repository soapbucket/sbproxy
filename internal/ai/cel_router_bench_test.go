package ai

import (
	"context"
	"testing"

	"github.com/soapbucket/sbproxy/internal/extension/cel"
)

func BenchmarkCELRouterEvaluate_SingleRule(b *testing.B) {
	router, err := NewCELRouter(&CELRoutingConfig{
		Rules: []CELRoutingRule{
			{
				Name:       "model-match",
				Expression: `ai.model.startsWith("gpt-4") && ai.message_count > 5`,
				Provider:   "openai",
			},
		},
		FallbackProvider: "default",
	})
	if err != nil {
		b.Fatalf("NewCELRouter() error: %v", err)
	}

	req := &ChatCompletionRequest{Model: "gpt-4-turbo"}
	vars := &cel.AIContextVars{
		Model:         "gpt-4-turbo",
		Provider:      "openai",
		MessageCount:  10,
		TokenEstimate: 1500,
		HasTools:      true,
		IsStreaming:    false,
		Budget: map[string]any{
			"utilization":      0.5,
			"remaining_tokens": int64(50000),
			"period":           "monthly",
		},
	}
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		router.Evaluate(ctx, req, vars)
	}
}

func BenchmarkCELRouterEvaluate_TenRules(b *testing.B) {
	rules := []CELRoutingRule{
		{Name: "r1", Expression: `ai.model == "gpt-4-turbo"`, Provider: "p1", Priority: 0},
		{Name: "r2", Expression: `ai.model == "gpt-4"`, Provider: "p2", Priority: 1},
		{Name: "r3", Expression: `ai.model.startsWith("claude")`, Provider: "p3", Priority: 2},
		{Name: "r4", Expression: `ai.has_tools && ai.is_streaming`, Provider: "p4", Priority: 3},
		{Name: "r5", Expression: `budget.utilization > 0.9`, Provider: "p5", Priority: 4},
		{Name: "r6", Expression: `ai.message_count > 100`, Provider: "p6", Priority: 5},
		{Name: "r7", Expression: `ai.token_estimate > 10000`, Provider: "p7", Priority: 6},
		{Name: "r8", Expression: `ai.model.contains("opus")`, Provider: "p8", Priority: 7},
		{Name: "r9", Expression: `ai.provider == "anthropic"`, Provider: "p9", Priority: 8},
		{Name: "r10", Expression: `ai.message_count < 2 && !ai.has_tools`, Provider: "p10", Priority: 9},
	}

	router, err := NewCELRouter(&CELRoutingConfig{
		Rules:            rules,
		FallbackProvider: "default",
	})
	if err != nil {
		b.Fatalf("NewCELRouter() error: %v", err)
	}

	// Use vars that will NOT match any rule to force full evaluation
	req := &ChatCompletionRequest{Model: "llama-3"}
	vars := &cel.AIContextVars{
		Model:         "llama-3",
		Provider:      "meta",
		MessageCount:  10,
		TokenEstimate: 1500,
		HasTools:      false,
		IsStreaming:    false,
		Budget: map[string]any{
			"utilization":      0.5,
			"remaining_tokens": int64(50000),
			"period":           "monthly",
		},
	}
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		router.Evaluate(ctx, req, vars)
	}
}
