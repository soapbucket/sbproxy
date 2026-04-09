package policy

import (
	"testing"
)

func TestMerge_NumericMax(t *testing.T) {
	policies := []*Policy{
		{ID: "p1", MaxInputTokens: 1000, RPM: 10, TPM: 5000},
		{ID: "p2", MaxInputTokens: 2000, RPM: 20, TPM: 3000},
	}
	merged := MergePolicies(policies)

	if merged.MaxInputTokens != 2000 {
		t.Errorf("expected MaxInputTokens=2000, got %d", merged.MaxInputTokens)
	}
	if merged.RPM != 20 {
		t.Errorf("expected RPM=20, got %d", merged.RPM)
	}
	if merged.TPM != 5000 {
		t.Errorf("expected TPM=5000, got %d", merged.TPM)
	}
}

func TestMerge_ModelsUnion(t *testing.T) {
	policies := []*Policy{
		{ID: "p1", AllowedModels: []string{"gpt-4o", "gpt-3.5-turbo"}},
		{ID: "p2", AllowedModels: []string{"claude-3-opus", "gpt-4o"}},
	}
	merged := MergePolicies(policies)

	// UNION: should have all unique reqctx.
	expected := map[string]bool{
		"gpt-4o":        true,
		"gpt-3.5-turbo": true,
		"claude-3-opus":  true,
	}
	if len(merged.AllowedModels) != len(expected) {
		t.Errorf("expected %d allowed models, got %d: %v", len(expected), len(merged.AllowedModels), merged.AllowedModels)
	}
	for _, m := range merged.AllowedModels {
		if !expected[m] {
			t.Errorf("unexpected model in union: %s", m)
		}
	}
}

func TestMerge_BlockedIntersection(t *testing.T) {
	policies := []*Policy{
		{ID: "p1", BlockedModels: []string{"gpt-4o", "claude-3-opus"}},
		{ID: "p2", BlockedModels: []string{"gpt-4o", "gemini-pro"}},
	}
	merged := MergePolicies(policies)

	// INTERSECTION: only gpt-4o is blocked by both.
	if len(merged.BlockedModels) != 1 {
		t.Errorf("expected 1 blocked model, got %d: %v", len(merged.BlockedModels), merged.BlockedModels)
	}
	if len(merged.BlockedModels) > 0 && merged.BlockedModels[0] != "gpt-4o" {
		t.Errorf("expected blocked model gpt-4o, got %s", merged.BlockedModels[0])
	}
}

func TestMerge_BooleanOR(t *testing.T) {
	tr := true
	f := false
	policies := []*Policy{
		{ID: "p1", AllowStreaming: &f, AllowTools: &tr},
		{ID: "p2", AllowStreaming: &tr, AllowTools: &f},
	}
	merged := MergePolicies(policies)

	// OR: if any allows, result is true.
	if merged.AllowStreaming == nil || !*merged.AllowStreaming {
		t.Error("expected AllowStreaming=true (OR of false|true)")
	}
	if merged.AllowTools == nil || !*merged.AllowTools {
		t.Error("expected AllowTools=true (OR of true|false)")
	}
}

func TestMerge_SinglePolicy(t *testing.T) {
	original := &Policy{
		ID:              "p1",
		Name:            "test",
		MaxInputTokens:  1000,
		AllowedModels:   []string{"gpt-4o"},
		BlockedProviders: []string{"azure"},
	}
	merged := MergePolicies([]*Policy{original})

	if merged.ID != original.ID {
		t.Errorf("expected ID=%s, got %s", original.ID, merged.ID)
	}
	if merged.MaxInputTokens != original.MaxInputTokens {
		t.Errorf("expected MaxInputTokens=%d, got %d", original.MaxInputTokens, merged.MaxInputTokens)
	}
}

func TestMerge_EmptyPolicies(t *testing.T) {
	merged := MergePolicies([]*Policy{})
	if merged == nil {
		t.Fatal("expected non-nil policy for empty input")
	}
	if merged.ID != "" {
		t.Errorf("expected empty ID, got %q", merged.ID)
	}
}

func TestMerge_Priority(t *testing.T) {
	policies := []*Policy{
		{ID: "p-low", Priority: 10, Name: "low-priority"},
		{ID: "p-high", Priority: 1, Name: "high-priority"},
		{ID: "p-med", Priority: 5, Name: "med-priority"},
	}
	merged := MergePolicies(policies)

	// The highest priority (lowest number) policy's ID and name should be the base.
	if merged.ID != "p-high" {
		t.Errorf("expected ID=p-high (highest priority), got %s", merged.ID)
	}
	if merged.Name != "high-priority" {
		t.Errorf("expected Name=high-priority, got %s", merged.Name)
	}
}

func TestMerge_BlockedIntersection_NoOverlap(t *testing.T) {
	policies := []*Policy{
		{ID: "p1", BlockedModels: []string{"gpt-4o"}},
		{ID: "p2", BlockedModels: []string{"claude-3-opus"}},
	}
	merged := MergePolicies(policies)

	// No overlap, so intersection should be empty.
	if len(merged.BlockedModels) != 0 {
		t.Errorf("expected 0 blocked models (no intersection), got %d: %v", len(merged.BlockedModels), merged.BlockedModels)
	}
}

func TestMerge_ProvidersUnionAndIntersection(t *testing.T) {
	policies := []*Policy{
		{ID: "p1", AllowedProviders: []string{"openai"}, BlockedProviders: []string{"azure", "bedrock"}},
		{ID: "p2", AllowedProviders: []string{"anthropic"}, BlockedProviders: []string{"azure"}},
	}
	merged := MergePolicies(policies)

	// UNION of allowed.
	allowedSet := make(map[string]bool)
	for _, p := range merged.AllowedProviders {
		allowedSet[p] = true
	}
	if !allowedSet["openai"] || !allowedSet["anthropic"] {
		t.Errorf("expected union of providers, got %v", merged.AllowedProviders)
	}

	// INTERSECTION of blocked.
	if len(merged.BlockedProviders) != 1 || merged.BlockedProviders[0] != "azure" {
		t.Errorf("expected [azure] blocked (intersection), got %v", merged.BlockedProviders)
	}
}

func TestMerge_GuardrailsRequired(t *testing.T) {
	policies := []*Policy{
		{ID: "p1", RequireGuardrails: false},
		{ID: "p2", RequireGuardrails: true},
	}
	merged := MergePolicies(policies)

	if !merged.RequireGuardrails {
		t.Error("expected RequireGuardrails=true (if any policy requires, all require)")
	}
}
