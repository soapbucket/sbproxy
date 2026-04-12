package mcp

import (
	"testing"
)

func TestAccessChecker_NoRules(t *testing.T) {
	ac := NewAccessChecker(nil)
	err := ac.Check("any_tool", []string{"admin"}, "key-1")
	if err != nil {
		t.Errorf("expected no error with no rules, got %v", err)
	}
}

func TestAccessChecker_NoRuleForTool(t *testing.T) {
	ac := NewAccessChecker(map[string]*ToolAccessConfig{
		"other_tool": {AllowedRoles: []string{"admin"}},
	})
	err := ac.Check("unrelated_tool", []string{"user"}, "")
	if err != nil {
		t.Errorf("expected no error for unconfigured tool, got %v", err)
	}
}

func TestAccessChecker_AllowedRole(t *testing.T) {
	ac := NewAccessChecker(map[string]*ToolAccessConfig{
		"search": {AllowedRoles: []string{"admin", "editor"}},
	})

	tests := []struct {
		name    string
		roles   []string
		keyID   string
		wantErr bool
	}{
		{"admin allowed", []string{"admin"}, "", false},
		{"editor allowed", []string{"editor"}, "", false},
		{"viewer denied", []string{"viewer"}, "", true},
		{"no roles denied", nil, "", true},
		{"multiple roles one match", []string{"viewer", "admin"}, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ac.Check("search", tt.roles, tt.keyID)
			if (err != nil) != tt.wantErr {
				t.Errorf("Check() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestAccessChecker_AllowedKeys(t *testing.T) {
	ac := NewAccessChecker(map[string]*ToolAccessConfig{
		"deploy": {AllowedKeys: []string{"key-prod", "key-staging"}},
	})

	tests := []struct {
		name    string
		roles   []string
		keyID   string
		wantErr bool
	}{
		{"matching key", nil, "key-prod", false},
		{"staging key", nil, "key-staging", false},
		{"wrong key", nil, "key-dev", true},
		{"no key", nil, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ac.Check("deploy", tt.roles, tt.keyID)
			if (err != nil) != tt.wantErr {
				t.Errorf("Check() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestAccessChecker_DeniedRoles(t *testing.T) {
	ac := NewAccessChecker(map[string]*ToolAccessConfig{
		"admin_tool": {
			AllowedRoles: []string{"admin"},
			DeniedRoles:  []string{"suspended"},
		},
	})

	tests := []struct {
		name    string
		roles   []string
		wantErr bool
	}{
		{"admin allowed", []string{"admin"}, false},
		{"suspended denied even with admin", []string{"admin", "suspended"}, true},
		{"only suspended denied", []string{"suspended"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ac.Check("admin_tool", tt.roles, "")
			if (err != nil) != tt.wantErr {
				t.Errorf("Check() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestAccessChecker_RoleOrKey(t *testing.T) {
	ac := NewAccessChecker(map[string]*ToolAccessConfig{
		"mixed": {
			AllowedRoles: []string{"admin"},
			AllowedKeys:  []string{"key-special"},
		},
	})

	tests := []struct {
		name    string
		roles   []string
		keyID   string
		wantErr bool
	}{
		{"role match", []string{"admin"}, "", false},
		{"key match", []string{"viewer"}, "key-special", false},
		{"neither", []string{"viewer"}, "key-other", true},
		{"both match", []string{"admin"}, "key-special", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ac.Check("mixed", tt.roles, tt.keyID)
			if (err != nil) != tt.wantErr {
				t.Errorf("Check() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestAccessChecker_EmptyAllowLists(t *testing.T) {
	// When only denied roles are set (no allowed roles/keys), everything else is allowed
	ac := NewAccessChecker(map[string]*ToolAccessConfig{
		"open_tool": {
			DeniedRoles: []string{"banned"},
		},
	})

	err := ac.Check("open_tool", []string{"random_user"}, "")
	if err != nil {
		t.Errorf("expected access allowed when only denied roles are set, got %v", err)
	}

	err = ac.Check("open_tool", []string{"banned"}, "")
	if err == nil {
		t.Error("expected access denied for banned role")
	}
}

func TestAccessChecker_HasRules(t *testing.T) {
	ac := NewAccessChecker(map[string]*ToolAccessConfig{
		"restricted": {AllowedRoles: []string{"admin"}},
	})

	if !ac.HasRules("restricted") {
		t.Error("expected HasRules to return true")
	}
	if ac.HasRules("unrestricted") {
		t.Error("expected HasRules to return false")
	}
}
