package keys

import (
	"testing"
)

func TestResolveGuardrails_KeyOverridesOrigin(t *testing.T) {
	keyGuards := []CELGuardrailConfig{
		{Name: "key-guard", Phase: "input", Condition: "true", Action: "block"},
	}
	originGuards := []CELGuardrailConfig{
		{Name: "origin-guard", Phase: "input", Condition: "true", Action: "flag"},
	}

	vk := &VirtualKey{
		ID:                    "key-1",
		GuardrailExpressions: keyGuards,
	}

	result := ResolveGuardrails(vk, originGuards)
	if len(result) != 1 {
		t.Fatalf("expected 1 guardrail, got %d", len(result))
	}
	if result[0].Name != "key-guard" {
		t.Errorf("expected key-guard, got %s", result[0].Name)
	}
}

func TestResolveGuardrails_NoKeyGuardrailsUsesDefaults(t *testing.T) {
	originGuards := []CELGuardrailConfig{
		{Name: "origin-guard", Phase: "output", Condition: "true", Action: "block"},
	}

	vk := &VirtualKey{
		ID: "key-2",
		// No guardrail expressions set
	}

	result := ResolveGuardrails(vk, originGuards)
	if len(result) != 1 {
		t.Fatalf("expected 1 guardrail, got %d", len(result))
	}
	if result[0].Name != "origin-guard" {
		t.Errorf("expected origin-guard, got %s", result[0].Name)
	}
}

func TestResolveGuardrails_NilKey(t *testing.T) {
	originGuards := []CELGuardrailConfig{
		{Name: "origin-guard", Phase: "input", Condition: "true", Action: "flag"},
	}

	result := ResolveGuardrails(nil, originGuards)
	if len(result) != 1 {
		t.Fatalf("expected 1 guardrail, got %d", len(result))
	}
	if result[0].Name != "origin-guard" {
		t.Errorf("expected origin-guard, got %s", result[0].Name)
	}
}
