package plugin_test

import (
	"encoding/json"
	"testing"

	"github.com/soapbucket/sbproxy/pkg/plugin"
	// Import all module registrations.
	_ "github.com/soapbucket/sbproxy/internal/modules"
)

// noopAliases lists registration names that are aliases for the noop handler.
// These are registered under alternate names (e.g., "", "none") but their
// Type() returns "noop". The conformance check allows this mismatch.
var noopAliases = map[string]bool{
	"":     true,
	"none": true,
}

func TestConformance_AllActionsHaveType(t *testing.T) {
	for _, name := range plugin.ListActions() {
		factory, ok := plugin.GetAction(name)
		if !ok {
			t.Errorf("action %q listed but not gettable", name)
			continue
		}

		// Create with minimal config.
		handler, err := factory(json.RawMessage(`{"type":"` + name + `"}`))
		if err != nil {
			// Some actions need more config - that's OK, skip.
			t.Logf("action %q needs more config: %v", name, err)
			continue
		}

		if handler.Type() != name && !noopAliases[name] {
			t.Errorf("action %q: Type() = %q, want %q", name, handler.Type(), name)
		}
	}
}

func TestConformance_AllAuthsHaveType(t *testing.T) {
	for _, name := range plugin.ListAuths() {
		factory, ok := plugin.GetAuth(name)
		if !ok {
			t.Errorf("auth %q listed but not gettable", name)
			continue
		}

		handler, err := factory(json.RawMessage(`{"type":"` + name + `"}`))
		if err != nil {
			t.Logf("auth %q needs more config: %v", name, err)
			continue
		}

		if handler.Type() != name && !noopAliases[name] {
			t.Errorf("auth %q: Type() = %q, want %q", name, handler.Type(), name)
		}
	}
}

func TestConformance_AllPoliciesHaveType(t *testing.T) {
	for _, name := range plugin.ListPolicies() {
		factory, ok := plugin.GetPolicy(name)
		if !ok {
			t.Errorf("policy %q listed but not gettable", name)
			continue
		}

		handler, err := factory(json.RawMessage(`{"type":"` + name + `"}`))
		if err != nil {
			t.Logf("policy %q needs more config: %v", name, err)
			continue
		}

		if handler.Type() != name && !noopAliases[name] {
			t.Errorf("policy %q: Type() = %q, want %q", name, handler.Type(), name)
		}
	}
}

func TestConformance_AllTransformsHaveType(t *testing.T) {
	for _, name := range plugin.ListTransforms() {
		factory, ok := plugin.GetTransform(name)
		if !ok {
			t.Errorf("transform %q listed but not gettable", name)
			continue
		}

		handler, err := factory(json.RawMessage(`{"type":"` + name + `"}`))
		if err != nil {
			t.Logf("transform %q needs more config: %v", name, err)
			continue
		}

		if handler.Type() != name && !noopAliases[name] {
			t.Errorf("transform %q: Type() = %q, want %q", name, handler.Type(), name)
		}
	}
}

func TestConformance_RegistryNotEmpty(t *testing.T) {
	actions := plugin.ListActions()
	auths := plugin.ListAuths()
	policies := plugin.ListPolicies()
	transforms := plugin.ListTransforms()

	if len(actions) == 0 {
		t.Error("no actions registered")
	}
	if len(auths) == 0 {
		t.Error("no auths registered")
	}
	if len(policies) == 0 {
		t.Error("no policies registered")
	}
	if len(transforms) == 0 {
		t.Error("no transforms registered")
	}

	t.Logf("Registered: %d actions, %d auths, %d policies, %d transforms",
		len(actions), len(auths), len(policies), len(transforms))
}
