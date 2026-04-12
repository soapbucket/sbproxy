package limits

import (
	"errors"
	"testing"
)

var errTest = errors.New("test subsystem error")

func TestFailurePolicy_NilPolicyAllows(t *testing.T) {
	var p *FailurePolicy
	if !p.ShouldAllow("anything", errTest) {
		t.Fatal("nil policy should fail open (allow)")
	}
}

func TestFailurePolicy_DefaultOpen(t *testing.T) {
	p := &FailurePolicy{Default: FailOpen}
	if !p.ShouldAllow("cache", errTest) {
		t.Fatal("default open policy should allow on error")
	}
}

func TestFailurePolicy_DefaultClosed(t *testing.T) {
	p := &FailurePolicy{Default: FailClosed}
	if p.ShouldAllow("cache", errTest) {
		t.Fatal("default closed policy should block on error")
	}
}

func TestFailurePolicy_OverrideTakesPrecedence(t *testing.T) {
	p := &FailurePolicy{
		Default: FailOpen,
		Overrides: map[string]FailureMode{
			"budget": FailClosed,
		},
	}
	if p.ShouldAllow("budget", errTest) {
		t.Fatal("override closed should block even when default is open")
	}
	if !p.ShouldAllow("cache", errTest) {
		t.Fatal("non-overridden subsystem should use default open")
	}
}

func TestFailurePolicy_UnknownSubsystemUsesDefault(t *testing.T) {
	p := &FailurePolicy{
		Default: FailClosed,
		Overrides: map[string]FailureMode{
			"budget": FailOpen,
		},
	}
	if p.ShouldAllow("unknown_subsystem", errTest) {
		t.Fatal("unknown subsystem should use default closed")
	}
}

func TestDefaultFailurePolicy(t *testing.T) {
	p := DefaultFailurePolicy()

	if p.Default != FailOpen {
		t.Fatalf("expected default mode open, got %s", p.Default)
	}

	closedSubsystems := []string{"budget", "guardrails", "lua_hooks"}
	for _, sub := range closedSubsystems {
		mode, ok := p.Overrides[sub]
		if !ok {
			t.Fatalf("expected override for %s", sub)
		}
		if mode != FailClosed {
			t.Fatalf("expected %s override to be closed, got %s", sub, mode)
		}
	}
}
