package identity

import (
	"testing"
)

func TestResolvedPermissions_CanAccessModel_Allowed(t *testing.T) {
	rp := &ResolvedPermissions{
		PrincipalID:   "user-1",
		AllowedModels: []string{"gpt-4o", "gpt-3.5-turbo"},
		DeniedModels:  nil,
		ModelLimits:   map[string]ModelLimit{},
	}

	if !rp.CanAccessModel("gpt-4o") {
		t.Error("expected gpt-4o to be allowed")
	}
	if !rp.CanAccessModel("gpt-3.5-turbo") {
		t.Error("expected gpt-3.5-turbo to be allowed")
	}
	if rp.CanAccessModel("claude-3-opus") {
		t.Error("expected claude-3-opus to be denied (not in allow list)")
	}
}

func TestResolvedPermissions_CanAccessModel_Denied(t *testing.T) {
	rp := &ResolvedPermissions{
		PrincipalID:   "user-1",
		AllowedModels: []string{"gpt-4o", "gpt-3.5-turbo"},
		DeniedModels:  []string{"gpt-4o"},
		ModelLimits:   map[string]ModelLimit{},
	}

	// Deny wins over allow.
	if rp.CanAccessModel("gpt-4o") {
		t.Error("expected gpt-4o to be denied (deny takes precedence)")
	}
	if !rp.CanAccessModel("gpt-3.5-turbo") {
		t.Error("expected gpt-3.5-turbo to be allowed")
	}
}

func TestResolvedPermissions_CanAccessModel_GlobPattern(t *testing.T) {
	rp := &ResolvedPermissions{
		PrincipalID:   "user-1",
		AllowedModels: []string{"gpt-4*", "claude-3-*"},
		DeniedModels:  []string{"gpt-4-preview*"},
		ModelLimits:   map[string]ModelLimit{},
	}

	if !rp.CanAccessModel("gpt-4o") {
		t.Error("expected gpt-4o to match gpt-4* allow pattern")
	}
	if !rp.CanAccessModel("claude-3-opus") {
		t.Error("expected claude-3-opus to match claude-3-* allow pattern")
	}
	if rp.CanAccessModel("gpt-4-preview-0125") {
		t.Error("expected gpt-4-preview-0125 to be denied by gpt-4-preview* deny pattern")
	}
	if rp.CanAccessModel("llama-3-70b") {
		t.Error("expected llama-3-70b to be denied (not in allow list)")
	}
}

func TestResolvedPermissions_CanAccessModel_EmptyAllows(t *testing.T) {
	// Empty allow list and empty deny list means all models are allowed.
	rp := &ResolvedPermissions{
		PrincipalID:   "user-1",
		AllowedModels: nil,
		DeniedModels:  nil,
		ModelLimits:   map[string]ModelLimit{},
	}

	if !rp.CanAccessModel("gpt-4o") {
		t.Error("expected gpt-4o to be allowed when no lists are set")
	}
	if !rp.CanAccessModel("any-model") {
		t.Error("expected any-model to be allowed when no lists are set")
	}

	// Empty allow list but non-empty deny list means all except denied.
	rp2 := &ResolvedPermissions{
		PrincipalID:   "user-2",
		AllowedModels: nil,
		DeniedModels:  []string{"gpt-4o"},
		ModelLimits:   map[string]ModelLimit{},
	}

	if rp2.CanAccessModel("gpt-4o") {
		t.Error("expected gpt-4o to be denied")
	}
	if !rp2.CanAccessModel("claude-3-opus") {
		t.Error("expected claude-3-opus to be allowed")
	}
}

func TestResolvedPermissions_CanAccessModel_Nil(t *testing.T) {
	var rp *ResolvedPermissions
	if rp.CanAccessModel("anything") {
		t.Error("nil ResolvedPermissions should deny all")
	}
}

func TestResolvedPermissions_GetModelLimit(t *testing.T) {
	rp := &ResolvedPermissions{
		PrincipalID: "user-1",
		ModelLimits: map[string]ModelLimit{
			"gpt-4o":   {MaxTokens: 4096, RPM: 60},
			"gpt-3.5*": {MaxTokens: 8192, RPM: 120},
		},
	}

	// Exact match.
	lim := rp.GetModelLimit("gpt-4o")
	if lim == nil {
		t.Fatal("expected limit for gpt-4o")
	}
	if lim.MaxTokens != 4096 {
		t.Errorf("expected MaxTokens 4096, got %d", lim.MaxTokens)
	}
	if lim.RPM != 60 {
		t.Errorf("expected RPM 60, got %d", lim.RPM)
	}

	// Glob match.
	lim2 := rp.GetModelLimit("gpt-3.5-turbo")
	if lim2 == nil {
		t.Fatal("expected limit for gpt-3.5-turbo via glob")
	}
	if lim2.MaxTokens != 8192 {
		t.Errorf("expected MaxTokens 8192, got %d", lim2.MaxTokens)
	}

	// No match.
	lim3 := rp.GetModelLimit("claude-3-opus")
	if lim3 != nil {
		t.Error("expected nil limit for claude-3-opus")
	}

	// Nil receiver.
	var nilRP *ResolvedPermissions
	if nilRP.GetModelLimit("gpt-4o") != nil {
		t.Error("nil receiver should return nil")
	}
}

func TestMergeGrants_AllowOnly(t *testing.T) {
	grants := []ModelGrant{
		{Model: "gpt-4o", Permission: "allow"},
		{Model: "gpt-3.5-turbo", Permission: "allow"},
	}

	allowed, denied, limits := MergeGrants(grants)

	if len(allowed) != 2 {
		t.Errorf("expected 2 allowed, got %d", len(allowed))
	}
	if len(denied) != 0 {
		t.Errorf("expected 0 denied, got %d", len(denied))
	}
	if len(limits) != 0 {
		t.Errorf("expected 0 limits, got %d", len(limits))
	}
}

func TestMergeGrants_DenyWins(t *testing.T) {
	grants := []ModelGrant{
		{Model: "gpt-4o", Permission: "allow", Priority: 0},
		{Model: "gpt-4o", Permission: "deny", Priority: 0},
	}

	allowed, denied, _ := MergeGrants(grants)

	if len(allowed) != 0 {
		t.Errorf("expected 0 allowed, got %d: %v", len(allowed), allowed)
	}
	if len(denied) != 1 || denied[0] != "gpt-4o" {
		t.Errorf("expected [gpt-4o] denied, got %v", denied)
	}
}

func TestMergeGrants_PriorityResolution(t *testing.T) {
	grants := []ModelGrant{
		{Model: "gpt-4o", Permission: "deny", Priority: 10},  // Lower priority
		{Model: "gpt-4o", Permission: "allow", Priority: 0},  // Higher priority (wins)
	}

	allowed, denied, _ := MergeGrants(grants)

	if len(allowed) != 1 || allowed[0] != "gpt-4o" {
		t.Errorf("expected [gpt-4o] allowed (higher priority wins), got allowed=%v denied=%v", allowed, denied)
	}
}

func TestMergeGrants_LimitsMostRestrictive(t *testing.T) {
	grants := []ModelGrant{
		{Model: "gpt-4o", Permission: "allow", MaxTokens: 8192, RPM: 100},
		{Model: "gpt-4o", Permission: "allow", MaxTokens: 4096, RPM: 60},
	}

	_, _, limits := MergeGrants(grants)

	lim, ok := limits["gpt-4o"]
	if !ok {
		t.Fatal("expected limits for gpt-4o")
	}
	if lim.MaxTokens != 4096 {
		t.Errorf("expected most restrictive MaxTokens 4096, got %d", lim.MaxTokens)
	}
	if lim.RPM != 60 {
		t.Errorf("expected most restrictive RPM 60, got %d", lim.RPM)
	}
}

func TestMergeGrants_GlobPatterns(t *testing.T) {
	grants := []ModelGrant{
		{Model: "gpt-4*", Permission: "allow"},
		{Model: "claude-*", Permission: "deny"},
	}

	allowed, denied, _ := MergeGrants(grants)

	if len(allowed) != 1 || allowed[0] != "gpt-4*" {
		t.Errorf("expected [gpt-4*] allowed, got %v", allowed)
	}
	if len(denied) != 1 || denied[0] != "claude-*" {
		t.Errorf("expected [claude-*] denied, got %v", denied)
	}
}

func TestMergeGrants_Empty(t *testing.T) {
	allowed, denied, limits := MergeGrants(nil)

	if len(allowed) != 0 {
		t.Errorf("expected 0 allowed, got %d", len(allowed))
	}
	if len(denied) != 0 {
		t.Errorf("expected 0 denied, got %d", len(denied))
	}
	if len(limits) != 0 {
		t.Errorf("expected 0 limits, got %d", len(limits))
	}
}
