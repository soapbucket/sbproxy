package builtin

import (
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestRegisterAll(t *testing.T) {
	resolver := policy.NewGuardrailResolver()
	executor := policy.NewGuardrailExecutor(resolver)

	RegisterAll(executor)

	// Verify all 22 detector types are registered by checking each type.
	expectedTypes := []string{
		"pii", "keyword", "regex", "length", "language", "code",
		"schema", "url", "secret", "injection", "jwt", "model",
		"request_type", "metadata", "params", "token_estimate",
		"tool_call", "response_length", "budget_gate", "gibberish",
		"webhook", "log",
	}

	for _, typ := range expectedTypes {
		// Try to evaluate with the type - if the detector is not registered,
		// the executor will skip it (no error, but no result either).
		// We test by setting up a guardrail config and checking we get a result.
		resolver.SetWorkspaceGuardrails([]*policy.GuardrailConfig{
			{
				ID:        "test-" + typ,
				Name:      "Test " + typ,
				Type:      typ,
				Action:    policy.GuardrailActionLog,
				Config:    map[string]any{},
				Enabled:   true,
				AppliesTo: "input",
			},
		})

		eval, err := executor.EvaluateInput(
			nil,
			nil,
			"",
			"test content",
			nil,
		)
		if err != nil {
			t.Errorf("detector %q returned error: %v", typ, err)
			continue
		}
		if len(eval.Results) == 0 {
			t.Errorf("detector %q not registered (no results)", typ)
		}
	}
}
