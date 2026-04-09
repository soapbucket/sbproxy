package policy

import (
	"context"
	"testing"
)

func benchPrincipal() Principal {
	return &testPrincipal{ID: "bench-user"}
}

func BenchmarkEngineEvaluate(b *testing.B) {
	engine := NewEngine()
	tr := true
	ec := &EvaluationContext{
		Principal:            benchPrincipal(),
		Model:                "gpt-4o",
		Provider:             "openai",
		InputTokens:          100,
		OutputTokens:         50,
		IsStreaming:           true,
		HasTools:             true,
		GuardrailsConfigured: true,
		Tags:                 map[string]string{"env": "prod", "team": "ml"},
	}
	policies := []*Policy{
		{
			ID:                "p1",
			AllowedModels:     []string{"gpt-4o", "gpt-3.5-turbo", "claude-3-opus"},
			AllowedProviders:  []string{"openai", "anthropic"},
			MaxInputTokens:    10000,
			MaxOutputTokens:   4000,
			MaxTotalTokens:    14000,
			RPM:               1000000, // High limit to avoid hitting it during benchmark
			TPM:               10000000,
			AllowStreaming:    &tr,
			AllowTools:        &tr,
			RequireGuardrails: true,
			RequiredTags:      map[string]string{"env": "*"},
		},
	}
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = engine.Evaluate(ctx, ec, policies)
	}
}

func BenchmarkEngineEvaluate_SinglePolicy(b *testing.B) {
	engine := NewEngine()
	ec := &EvaluationContext{
		Principal:   benchPrincipal(),
		Model:       "gpt-4o",
		InputTokens: 100,
	}
	policies := []*Policy{{
		ID:             "p1",
		MaxInputTokens: 10000,
	}}
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = engine.Evaluate(ctx, ec, policies)
	}
}
