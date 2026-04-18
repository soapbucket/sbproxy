package routing

import (
	"testing"
)

func TestSelectFreeTierFirst(t *testing.T) {
	cfg := FreeTierConfig{
		FreeTierProviders: []string{"google-gemini", "cloudflare-ai"},
		PaidProviders:     []string{"openai", "anthropic"},
	}

	result := SelectFreeTierFirst(cfg)

	expected := []string{"google-gemini", "cloudflare-ai", "openai", "anthropic"}
	if len(result) != len(expected) {
		t.Fatalf("expected %d providers, got %d", len(expected), len(result))
	}

	for i, provider := range expected {
		if result[i] != provider {
			t.Errorf("position %d: expected %q, got %q", i, provider, result[i])
		}
	}
}

func TestSelectFreeTierFirst_OnlyFree(t *testing.T) {
	cfg := FreeTierConfig{
		FreeTierProviders: []string{"google-gemini"},
	}

	result := SelectFreeTierFirst(cfg)
	if len(result) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(result))
	}
	if result[0] != "google-gemini" {
		t.Errorf("expected 'google-gemini', got %q", result[0])
	}
}

func TestSelectFreeTierFirst_OnlyPaid(t *testing.T) {
	cfg := FreeTierConfig{
		PaidProviders: []string{"openai", "anthropic"},
	}

	result := SelectFreeTierFirst(cfg)
	if len(result) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(result))
	}
	if result[0] != "openai" {
		t.Errorf("expected 'openai' first, got %q", result[0])
	}
}

func TestSelectFreeTierFirst_Empty(t *testing.T) {
	cfg := FreeTierConfig{}

	result := SelectFreeTierFirst(cfg)
	if len(result) != 0 {
		t.Errorf("expected 0 providers, got %d", len(result))
	}
}
