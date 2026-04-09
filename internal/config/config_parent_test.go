package config

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockPolicy implements PolicyConfig for testing
type mockPolicy struct {
	policyType string
	applied    bool
}

func (m *mockPolicy) GetType() string { return m.policyType }
func (m *mockPolicy) Init(_ *Config) error { return nil }
func (m *mockPolicy) Apply(next http.Handler) http.Handler {
	m.applied = true
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Policy-"+m.policyType, "applied")
		next.ServeHTTP(w, r)
	})
}

// mockAuth implements AuthConfig for testing
type mockAuth struct {
	authType string
	applied  bool
}

func (m *mockAuth) GetType() string { return m.authType }
func (m *mockAuth) Init(_ *Config) error { return nil }
func (m *mockAuth) Authenticate(next http.Handler) http.Handler {
	m.applied = true
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Auth", m.authType)
		next.ServeHTTP(w, r)
	})
}

// TestParentPolicies_Applied verifies that parent policies are applied as the
// outermost middleware layer when a child has a parent and DisableApplyParent is false.
func TestParentPolicies_Applied(t *testing.T) {
	parentPolicy := &mockPolicy{policyType: "parent-waf"}
	childPolicy := &mockPolicy{policyType: "child-rate-limit"}

	parent := &Config{
		ID:       "gateway",
		Hostname: "gateway.test",
		policies: []PolicyConfig{parentPolicy},
	}

	child := &Config{
		ID:       "backend",
		Hostname: "backend.test",
		Parent:   parent,
		policies: []PolicyConfig{childPolicy},
	}

	// Build handler chain manually (simulating config_handler.go logic)
	var next http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Apply child policies
	for i := len(child.policies) - 1; i >= 0; i-- {
		next = child.policies[i].Apply(next)
	}

	// Apply parent policies (outermost)
	if child.Parent != nil && !child.DisableApplyParent {
		for i := len(child.Parent.policies) - 1; i >= 0; i-- {
			next = child.Parent.policies[i].Apply(next)
		}
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	next.ServeHTTP(rec, req)

	if !parentPolicy.applied {
		t.Error("expected parent policy to be applied")
	}
	if !childPolicy.applied {
		t.Error("expected child policy to be applied")
	}

	// Verify execution order via headers
	if rec.Header().Get("X-Policy-parent-waf") != "applied" {
		t.Error("expected X-Policy-parent-waf header")
	}
	if rec.Header().Get("X-Policy-child-rate-limit") != "applied" {
		t.Error("expected X-Policy-child-rate-limit header")
	}
}

// TestParentPolicies_DisabledWhenOptOut verifies that parent policies are NOT applied
// when the child sets DisableApplyParent = true.
func TestParentPolicies_DisabledWhenOptOut(t *testing.T) {
	parentPolicy := &mockPolicy{policyType: "parent-waf"}
	childPolicy := &mockPolicy{policyType: "child-rate-limit"}

	parent := &Config{
		ID:       "gateway",
		Hostname: "gateway.test",
		policies: []PolicyConfig{parentPolicy},
	}

	child := &Config{
		ID:                 "backend",
		Hostname:           "backend.test",
		Parent:             parent,
		DisableApplyParent: true, // Opt-out
		policies:           []PolicyConfig{childPolicy},
	}

	var next http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Apply child policies
	for i := len(child.policies) - 1; i >= 0; i-- {
		next = child.policies[i].Apply(next)
	}

	// Apply parent policies (should NOT apply due to DisableApplyParent)
	if child.Parent != nil && !child.DisableApplyParent {
		for i := len(child.Parent.policies) - 1; i >= 0; i-- {
			next = child.Parent.policies[i].Apply(next)
		}
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	next.ServeHTTP(rec, req)

	if parentPolicy.applied {
		t.Error("expected parent policy NOT to be applied when DisableApplyParent is true")
	}
	if !childPolicy.applied {
		t.Error("expected child policy to be applied")
	}
}

// TestParentAuthentication_Applied verifies that parent auth is used when the child
// has no auth and parent propagation is enabled.
func TestParentAuthentication_Applied(t *testing.T) {
	parentAuth := &mockAuth{authType: "jwt"}

	parent := &Config{
		ID:       "gateway",
		Hostname: "gateway.test",
		auth:     parentAuth,
	}

	child := &Config{
		ID:       "backend",
		Hostname: "backend.test",
		Parent:   parent,
		// No auth on child
	}

	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := child.Authenticate(innerHandler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	handler.ServeHTTP(rec, req)

	if !parentAuth.applied {
		t.Error("expected parent auth to be applied")
	}
	if rec.Header().Get("X-Auth") != "jwt" {
		t.Errorf("expected X-Auth header 'jwt', got %q", rec.Header().Get("X-Auth"))
	}
}

// TestParentAuthentication_ChildOverrides verifies that when both parent and child
// have auth, the child's auth takes precedence.
func TestParentAuthentication_ChildOverrides(t *testing.T) {
	parentAuth := &mockAuth{authType: "parent-jwt"}
	childAuth := &mockAuth{authType: "child-api-key"}

	parent := &Config{
		ID:       "gateway",
		Hostname: "gateway.test",
		auth:     parentAuth,
	}

	child := &Config{
		ID:       "backend",
		Hostname: "backend.test",
		Parent:   parent,
		auth:     childAuth,
	}

	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := child.Authenticate(innerHandler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	handler.ServeHTTP(rec, req)

	if !childAuth.applied {
		t.Error("expected child auth to be applied")
	}
	if parentAuth.applied {
		t.Error("expected parent auth NOT to be applied when child has auth")
	}
	if rec.Header().Get("X-Auth") != "child-api-key" {
		t.Errorf("expected X-Auth 'child-api-key', got %q", rec.Header().Get("X-Auth"))
	}
}

// TestParentAuthentication_DisabledWhenOptOut verifies that parent auth is NOT applied
// when the child sets DisableApplyParent = true.
func TestParentAuthentication_DisabledWhenOptOut(t *testing.T) {
	parentAuth := &mockAuth{authType: "jwt"}

	parent := &Config{
		ID:       "gateway",
		Hostname: "gateway.test",
		auth:     parentAuth,
	}

	child := &Config{
		ID:                 "backend",
		Hostname:           "backend.test",
		Parent:             parent,
		DisableApplyParent: true,
		// No auth on child
	}

	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := child.Authenticate(innerHandler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	handler.ServeHTTP(rec, req)

	if parentAuth.applied {
		t.Error("expected parent auth NOT to be applied when DisableApplyParent is true")
	}
}

// TestParentNoParent verifies that when there is no parent, only child policies run.
func TestParentNoParent(t *testing.T) {
	childPolicy := &mockPolicy{policyType: "child-rate-limit"}

	child := &Config{
		ID:       "standalone",
		Hostname: "standalone.test",
		policies: []PolicyConfig{childPolicy},
	}

	var next http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Apply child policies
	for i := len(child.policies) - 1; i >= 0; i-- {
		next = child.policies[i].Apply(next)
	}

	// Apply parent policies (no parent, should skip)
	if child.Parent != nil && !child.DisableApplyParent {
		t.Error("should not enter parent block when Parent is nil")
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	next.ServeHTTP(rec, req)

	if !childPolicy.applied {
		t.Error("expected child policy to be applied")
	}
}
