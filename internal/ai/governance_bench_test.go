package ai

import (
	"context"
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func BenchmarkBudgetScopeValues(b *testing.B) {
	h := &Handler{}
	rd := reqctx.NewRequestData()
	rd.Config["workspace_id"] = "ws-bench"
	rd.Config["id"] = "origin-bench"
	rd.AddDebugHeader("X-Sb-AI-User", "user-123")
	rd.SessionData = &reqctx.SessionData{
		AuthData: &reqctx.AuthData{
			Data: map[string]any{
				"key_id": "key-123",
			},
		},
	}
	ctx := reqctx.SetRequestData(context.Background(), rd)
	tags := map[string]string{
		"team":    "platform",
		"service": "assistant",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.budgetScopeValues(ctx, "gpt-4o", tags)
	}
}

func BenchmarkProviderExclusions_WithPolicy(b *testing.B) {
	h := &Handler{
		config: &HandlerConfig{
			AllowedProviders: []string{"openai-east", "openai-west", "bedrock-us"},
			ProviderPolicy: map[string]any{
				"allowed_regions": []any{"us-east-1"},
			},
		},
		providers: map[string]providerEntry{
			"openai-east": {config: &ProviderConfig{Name: "openai-east", Type: "openai", Region: "us-east-1"}},
			"openai-west": {config: &ProviderConfig{Name: "openai-west", Type: "openai", Region: "us-west-2"}},
			"bedrock-us":  {config: &ProviderConfig{Name: "bedrock-us", Type: "bedrock", Region: "us-east-1"}},
		},
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.providerExclusions(ctx)
	}
}
