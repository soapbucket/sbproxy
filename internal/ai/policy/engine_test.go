package policy

import (
	"context"
	"testing"
	"time"
)

// testPrincipal implements the Principal interface for testing.
type testPrincipal struct {
	ID        string
	Expired   bool
	ExpiresAt *time.Time
}

func (p *testPrincipal) GetID() string { return p.ID }
func (p *testPrincipal) IsExpired() bool {
	if p.ExpiresAt != nil {
		return time.Now().After(*p.ExpiresAt)
	}
	return p.Expired
}

func validPrincipal() Principal {
	return &testPrincipal{ID: "user-1"}
}

func expiredPrincipal() Principal {
	exp := time.Now().Add(-time.Hour)
	return &testPrincipal{ID: "user-expired", ExpiresAt: &exp}
}

func TestEngine_AllStagesPass(t *testing.T) {
	engine := NewEngine()
	ec := &EvaluationContext{
		Principal:            validPrincipal(),
		Model:                "gpt-4o",
		Provider:             "openai",
		InputTokens:          100,
		OutputTokens:         50,
		GuardrailsConfigured: true,
		Tags:                 map[string]string{"env": "prod"},
	}
	policies := []*Policy{
		{
			ID:                "p1",
			Name:              "dev-policy",
			AllowedModels:     []string{"gpt-4o", "gpt-3.5-turbo"},
			MaxInputTokens:    1000,
			RequireGuardrails: true,
			RequiredTags:      map[string]string{"env": "*"},
		},
	}

	result, err := engine.Evaluate(context.Background(), ec, policies)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("expected allowed, got denied by %q: %s", result.DeniedBy, result.Reason)
	}
	if len(result.AppliedPolicies) != 1 || result.AppliedPolicies[0] != "p1" {
		t.Errorf("expected applied policies [p1], got %v", result.AppliedPolicies)
	}
}

func TestEngine_IdentityValidation_NilPrincipal(t *testing.T) {
	engine := NewEngine()
	ec := &EvaluationContext{
		Principal: nil,
		Model:     "gpt-4o",
	}
	policies := []*Policy{{ID: "p1"}}

	result, err := engine.Evaluate(context.Background(), ec, policies)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("expected denied for nil principal")
	}
	if result.DeniedBy != "identity_validation" {
		t.Errorf("expected denied by identity_validation, got %q", result.DeniedBy)
	}
}

func TestEngine_IdentityValidation_Expired(t *testing.T) {
	engine := NewEngine()
	ec := &EvaluationContext{
		Principal: expiredPrincipal(),
		Model:     "gpt-4o",
	}
	policies := []*Policy{{ID: "p1"}}

	result, err := engine.Evaluate(context.Background(), ec, policies)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("expected denied for expired principal")
	}
	if result.DeniedBy != "identity_validation" {
		t.Errorf("expected denied by identity_validation, got %q", result.DeniedBy)
	}
}

func TestEngine_ModelAccess_Allowed(t *testing.T) {
	engine := NewEngine()
	ec := &EvaluationContext{
		Principal: validPrincipal(),
		Model:     "gpt-4o",
	}
	policies := []*Policy{{
		ID:            "p1",
		AllowedModels: []string{"gpt-4o", "gpt-3.5-turbo"},
	}}

	result, err := engine.Evaluate(context.Background(), ec, policies)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("expected allowed, got denied: %s", result.Reason)
	}
}

func TestEngine_ModelAccess_Blocked(t *testing.T) {
	engine := NewEngine()
	ec := &EvaluationContext{
		Principal: validPrincipal(),
		Model:     "gpt-4o",
	}
	policies := []*Policy{{
		ID:            "p1",
		BlockedModels: []string{"gpt-4o"},
	}}

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
}

func TestEngine_ModelAccess_NotInAllowList(t *testing.T) {
	engine := NewEngine()
	ec := &EvaluationContext{
		Principal: validPrincipal(),
		Model:     "claude-3-opus",
	}
	policies := []*Policy{{
		ID:            "p1",
		AllowedModels: []string{"gpt-4o", "gpt-3.5-turbo"},
	}}

	result, err := engine.Evaluate(context.Background(), ec, policies)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("expected denied for model not in allow list")
	}
}

func TestEngine_ModelAccess_Wildcard(t *testing.T) {
	engine := NewEngine()
	ec := &EvaluationContext{
		Principal: validPrincipal(),
		Model:     "gpt-4o-mini",
	}
	policies := []*Policy{{
		ID:            "p1",
		AllowedModels: []string{"gpt-4*"},
	}}

	result, err := engine.Evaluate(context.Background(), ec, policies)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("expected allowed for wildcard match, got denied: %s", result.Reason)
	}
}

func TestEngine_ProviderAccess(t *testing.T) {
	engine := NewEngine()

	t.Run("allowed", func(t *testing.T) {
		ec := &EvaluationContext{
			Principal: validPrincipal(),
			Provider:  "openai",
		}
		policies := []*Policy{{
			ID:               "p1",
			AllowedProviders: []string{"openai", "anthropic"},
		}}
		result, err := engine.Evaluate(context.Background(), ec, policies)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("expected allowed, got denied: %s", result.Reason)
		}
	})

	t.Run("blocked", func(t *testing.T) {
		ec := &EvaluationContext{
			Principal: validPrincipal(),
			Provider:  "openai",
		}
		policies := []*Policy{{
			ID:               "p1",
			BlockedProviders: []string{"openai"},
		}}
		result, err := engine.Evaluate(context.Background(), ec, policies)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Error("expected denied for blocked provider")
		}
		if result.DeniedBy != "provider_access" {
			t.Errorf("expected denied by provider_access, got %q", result.DeniedBy)
		}
	})
}

func TestEngine_FeatureGating_StreamingDenied(t *testing.T) {
	engine := NewEngine()
	f := false
	ec := &EvaluationContext{
		Principal:   validPrincipal(),
		IsStreaming: true,
	}
	policies := []*Policy{{
		ID:             "p1",
		AllowStreaming: &f,
	}}

	result, err := engine.Evaluate(context.Background(), ec, policies)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("expected denied for streaming")
	}
	if result.DeniedBy != "feature_gating" {
		t.Errorf("expected denied by feature_gating, got %q", result.DeniedBy)
	}
}

func TestEngine_FeatureGating_ToolsDenied(t *testing.T) {
	engine := NewEngine()
	f := false
	ec := &EvaluationContext{
		Principal: validPrincipal(),
		HasTools:  true,
	}
	policies := []*Policy{{
		ID:         "p1",
		AllowTools: &f,
	}}

	result, err := engine.Evaluate(context.Background(), ec, policies)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("expected denied for tools")
	}
	if result.DeniedBy != "feature_gating" {
		t.Errorf("expected denied by feature_gating, got %q", result.DeniedBy)
	}
}

func TestEngine_FeatureGating_AllowedByDefault(t *testing.T) {
	engine := NewEngine()
	ec := &EvaluationContext{
		Principal:   validPrincipal(),
		IsStreaming: true,
		HasTools:    true,
		HasImages:   true,
	}
	// No feature flags set - should be allowed by default.
	policies := []*Policy{{ID: "p1"}}

	result, err := engine.Evaluate(context.Background(), ec, policies)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("expected allowed by default, got denied: %s", result.Reason)
	}
}

func TestEngine_TokenLimits_Exceeded(t *testing.T) {
	engine := NewEngine()
	ec := &EvaluationContext{
		Principal:   validPrincipal(),
		InputTokens: 5000,
	}
	policies := []*Policy{{
		ID:             "p1",
		MaxInputTokens: 1000,
	}}

	result, err := engine.Evaluate(context.Background(), ec, policies)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("expected denied for token limit exceeded")
	}
	if result.DeniedBy != "token_limits" {
		t.Errorf("expected denied by token_limits, got %q", result.DeniedBy)
	}
}

func TestEngine_TokenLimits_TotalExceeded(t *testing.T) {
	engine := NewEngine()
	ec := &EvaluationContext{
		Principal:    validPrincipal(),
		InputTokens:  600,
		OutputTokens: 600,
	}
	policies := []*Policy{{
		ID:             "p1",
		MaxTotalTokens: 1000,
	}}

	result, err := engine.Evaluate(context.Background(), ec, policies)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("expected denied for total token limit exceeded")
	}
}

func TestEngine_RateLimiting(t *testing.T) {
	engine := NewEngine()
	ec := &EvaluationContext{
		Principal: validPrincipal(),
	}
	policies := []*Policy{{
		ID:  "p1",
		RPM: 2,
	}}

	// First two requests should pass.
	for i := 0; i < 2; i++ {
		result, err := engine.Evaluate(context.Background(), ec, policies)
		if err != nil {
			t.Fatalf("request %d: unexpected error: %v", i+1, err)
		}
		if !result.Allowed {
			t.Errorf("request %d: expected allowed, got denied: %s", i+1, result.Reason)
		}
	}

	// Third request should be denied.
	result, err := engine.Evaluate(context.Background(), ec, policies)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("expected denied for RPM limit exceeded")
	}
	if result.DeniedBy != "rate_limiting" {
		t.Errorf("expected denied by rate_limiting, got %q", result.DeniedBy)
	}
}

func TestEngine_TPMLimiting(t *testing.T) {
	// Create engine with a fresh TPM limiter to avoid state leakage.
	tpmStage := &tpmLimitingStage{tpm: NewTPMLimiter()}
	engine := NewEngineWithStages(
		&identityValidationStage{},
		tpmStage,
	)
	ec := &EvaluationContext{
		Principal:   validPrincipal(),
		InputTokens: 600,
	}
	policies := []*Policy{{
		ID:  "p1",
		TPM: 1000,
	}}

	// First request: 600 tokens, should pass.
	result, err := engine.Evaluate(context.Background(), ec, policies)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("expected allowed, got denied: %s", result.Reason)
	}

	// Second request: 600 more tokens (total 1200), should be denied.
	result, err = engine.Evaluate(context.Background(), ec, policies)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("expected denied for TPM limit exceeded")
	}
	if result.DeniedBy != "tpm_limiting" {
		t.Errorf("expected denied by tpm_limiting, got %q", result.DeniedBy)
	}
}

func TestEngine_GuardrailRequired(t *testing.T) {
	engine := NewEngine()
	ec := &EvaluationContext{
		Principal:            validPrincipal(),
		GuardrailsConfigured: false,
	}
	policies := []*Policy{{
		ID:                "p1",
		RequireGuardrails: true,
	}}

	result, err := engine.Evaluate(context.Background(), ec, policies)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("expected denied when guardrails required but not configured")
	}
	if result.DeniedBy != "guardrail_requirement" {
		t.Errorf("expected denied by guardrail_requirement, got %q", result.DeniedBy)
	}
}

func TestEngine_ShortCircuit(t *testing.T) {
	// If identity validation fails, later stages should not run.
	engine := NewEngine()
	ec := &EvaluationContext{
		Principal:   nil, // Will fail identity validation
		InputTokens: 99999,
	}
	policies := []*Policy{{
		ID:             "p1",
		MaxInputTokens: 100,
	}}

	result, err := engine.Evaluate(context.Background(), ec, policies)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("expected denied")
	}
	// Should be denied by identity_validation, not token_limits.
	if result.DeniedBy != "identity_validation" {
		t.Errorf("expected denied by identity_validation (short circuit), got %q", result.DeniedBy)
	}
}

func TestEngine_MultiplePolicies(t *testing.T) {
	engine := NewEngine()
	ec := &EvaluationContext{
		Principal: validPrincipal(),
		Model:     "gpt-4o",
	}
	policies := []*Policy{
		{
			ID:            "p1",
			AllowedModels: []string{"gpt-4o"},
		},
		{
			ID:            "p2",
			AllowedModels: []string{"claude-3-opus"},
		},
	}

	// gpt-4o is in p1's allow list, so it should pass.
	result, err := engine.Evaluate(context.Background(), ec, policies)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("expected allowed (union of allow lists), got denied: %s", result.Reason)
	}
	if len(result.AppliedPolicies) != 2 {
		t.Errorf("expected 2 applied policies, got %d", len(result.AppliedPolicies))
	}
}

func TestEngine_EmptyPolicies(t *testing.T) {
	engine := NewEngine()
	ec := &EvaluationContext{
		Principal: validPrincipal(),
		Model:     "anything",
	}

	// No policies means allow all.
	result, err := engine.Evaluate(context.Background(), ec, []*Policy{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("expected allowed with empty policies, got denied: %s", result.Reason)
	}
}

func TestEngine_TagValidation(t *testing.T) {
	engine := NewEngine()

	t.Run("missing required tag", func(t *testing.T) {
		ec := &EvaluationContext{
			Principal: validPrincipal(),
			Tags:      map[string]string{},
		}
		policies := []*Policy{{
			ID:           "p1",
			RequiredTags: map[string]string{"env": "prod"},
		}}

		result, err := engine.Evaluate(context.Background(), ec, policies)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Error("expected denied for missing required tag")
		}
		if result.DeniedBy != "tag_validation" {
			t.Errorf("expected denied by tag_validation, got %q", result.DeniedBy)
		}
	})

	t.Run("wrong tag value", func(t *testing.T) {
		ec := &EvaluationContext{
			Principal: validPrincipal(),
			Tags:      map[string]string{"env": "dev"},
		}
		policies := []*Policy{{
			ID:           "p1",
			RequiredTags: map[string]string{"env": "prod"},
		}}

		result, err := engine.Evaluate(context.Background(), ec, policies)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Error("expected denied for wrong tag value")
		}
	})

	t.Run("wildcard tag", func(t *testing.T) {
		ec := &EvaluationContext{
			Principal: validPrincipal(),
			Tags:      map[string]string{"env": "anything"},
		}
		policies := []*Policy{{
			ID:           "p1",
			RequiredTags: map[string]string{"env": "*"},
		}}

		result, err := engine.Evaluate(context.Background(), ec, policies)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("expected allowed for wildcard tag, got denied: %s", result.Reason)
		}
	})
}
