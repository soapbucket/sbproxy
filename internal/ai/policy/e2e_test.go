package policy

import (
	"context"
	"testing"
)

// TestPolicyEngine_ModelAccess_E2E verifies end-to-end policy evaluation for model access
// control across multiple policies, principals, and stage interactions.
func TestPolicyEngine_ModelAccess_E2E(t *testing.T) {
	t.Run("full pipeline with model allow list", func(t *testing.T) {
		engine := NewEngine()

		principal := &testPrincipal{ID: "e2e-user-1"}
		ec := &EvaluationContext{
			Principal:            principal,
			Model:                "gpt-4o",
			Provider:             "openai",
			InputTokens:          500,
			OutputTokens:         200,
			GuardrailsConfigured: true,
			Tags:                 map[string]string{"env": "production", "team": "ml"},
		}

		// Simulate multi-group policies (user belongs to "developers" and "ml-team").
		developerPolicy := &Policy{
			ID:               "dev-policy",
			Name:             "Developer Policy",
			Priority:         10,
			AllowedModels:    []string{"gpt-3.5-turbo", "gpt-4o-mini"},
			AllowedProviders: []string{"openai"},
			MaxInputTokens:   2000,
			MaxOutputTokens:  1000,
			RPM:              60,
			TPM:              50000,
		}
		mlTeamPolicy := &Policy{
			ID:               "ml-policy",
			Name:             "ML Team Policy",
			Priority:         5,
			AllowedModels:    []string{"gpt-4o", "claude-3-opus"},
			AllowedProviders: []string{"openai", "anthropic"},
			MaxInputTokens:   8000,
			MaxOutputTokens:  4000,
			RPM:              120,
			TPM:              200000,
			RequireGuardrails: true,
			RequiredTags:      map[string]string{"env": "*"},
		}

		policies := []*Policy{developerPolicy, mlTeamPolicy}

		// gpt-4o is in ml-policy's allow list (union of allowed models).
		result, err := engine.Evaluate(context.Background(), ec, policies)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("expected allowed, got denied by %q: %s", result.DeniedBy, result.Reason)
		}
		if len(result.AppliedPolicies) != 2 {
			t.Errorf("expected 2 applied policies, got %d", len(result.AppliedPolicies))
		}
	})

	t.Run("blocked model denied across pipeline", func(t *testing.T) {
		engine := NewEngine()

		principal := &testPrincipal{ID: "e2e-user-2"}
		ec := &EvaluationContext{
			Principal: principal,
			Model:     "gpt-4o",
			Provider:  "openai",
		}

		policies := []*Policy{
			{
				ID:            "strict-policy",
				BlockedModels: []string{"gpt-4o", "gpt-4-turbo"},
			},
		}

		result, err := engine.Evaluate(context.Background(), ec, policies)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Error("expected denied for blocked model")
		}
		if result.DeniedBy != "model_access" {
			t.Errorf("expected denied by model_access, got %q", result.DeniedBy)
		}
	})

	t.Run("merged policies grant broader access", func(t *testing.T) {
		// Verify merge + evaluate flow works end-to-end.
		p1 := &Policy{
			ID:               "p1",
			Priority:         10,
			AllowedModels:    []string{"gpt-3.5-turbo"},
			MaxInputTokens:   1000,
			RPM:              30,
		}
		p2 := &Policy{
			ID:               "p2",
			Priority:         5,
			AllowedModels:    []string{"gpt-4o"},
			MaxInputTokens:   4000,
			RPM:              60,
		}

		merged := MergePolicies([]*Policy{p1, p2})

		// Verify merge results.
		if merged.MaxInputTokens != 4000 {
			t.Errorf("expected merged MaxInputTokens=4000, got %d", merged.MaxInputTokens)
		}
		if merged.RPM != 60 {
			t.Errorf("expected merged RPM=60, got %d", merged.RPM)
		}

		// Now evaluate with the merged policy.
		engine := NewEngine()
		ec := &EvaluationContext{
			Principal:   &testPrincipal{ID: "merge-user"},
			Model:       "gpt-4o",
			InputTokens: 2000,
		}

		result, err := engine.Evaluate(context.Background(), ec, []*Policy{merged})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("expected allowed with merged policy, got denied: %s", result.Reason)
		}
	})

	t.Run("expired principal denied before model check", func(t *testing.T) {
		engine := NewEngine()

		ec := &EvaluationContext{
			Principal: expiredPrincipal(),
			Model:     "gpt-4o",
		}
		policies := []*Policy{{
			ID:            "p1",
			AllowedModels: []string{"gpt-4o"},
		}}

		result, err := engine.Evaluate(context.Background(), ec, policies)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Error("expected denied for expired principal")
		}
		// Short-circuit: identity check runs before model access.
		if result.DeniedBy != "identity_validation" {
			t.Errorf("expected denied by identity_validation, got %q", result.DeniedBy)
		}
	})

	t.Run("token limit with TPM interaction", func(t *testing.T) {
		// Create fresh engine with isolated TPM state.
		tpmStage := &tpmLimitingStage{tpm: NewTPMLimiter()}
		engine := NewEngineWithStages(
			&identityValidationStage{},
			&modelAccessStage{},
			&tokenLimitsStage{},
			tpmStage,
		)

		principal := &testPrincipal{ID: "tpm-user"}
		policies := []*Policy{{
			ID:             "p1",
			AllowedModels:  []string{"gpt-4o"},
			MaxInputTokens: 5000,
			TPM:            10000,
		}}

		// Send 5 requests of 1500 tokens each. Per-request limit is 5000, so each passes.
		// But TPM is 10000, so the 7th request (cumulative 10500) should fail.
		for i := 0; i < 6; i++ {
			ec := &EvaluationContext{
				Principal:   principal,
				Model:       "gpt-4o",
				InputTokens: 1500,
			}
			result, err := engine.Evaluate(context.Background(), ec, policies)
			if err != nil {
				t.Fatalf("request %d: unexpected error: %v", i+1, err)
			}
			if i < 6 && !result.Allowed {
				t.Errorf("request %d: expected allowed, got denied: %s", i+1, result.Reason)
			}
		}

		// 7th request should be denied by TPM (6*1500=9000 recorded, +1500 = 10500 > 10000).
		ec := &EvaluationContext{
			Principal:   principal,
			Model:       "gpt-4o",
			InputTokens: 1500,
		}
		result, err := engine.Evaluate(context.Background(), ec, policies)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Error("expected denied by TPM limit")
		}
		if result.DeniedBy != "tpm_limiting" {
			t.Errorf("expected denied by tpm_limiting, got %q", result.DeniedBy)
		}
	})
}
