package rbac

import (
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/keys"
)

func TestCheckAccess_AdminBypasses(t *testing.T) {
	vk := &keys.VirtualKey{ID: "k1", Role: "admin", Status: "active"}
	if err := CheckAccess(vk); err != nil {
		t.Errorf("admin should be allowed, got %v", err)
	}
	if !IsAdmin(vk) {
		t.Error("expected IsAdmin=true for admin role")
	}
}

func TestCheckAccess_UserEnforced(t *testing.T) {
	vk := &keys.VirtualKey{ID: "k2", Role: "user", Status: "active"}
	if err := CheckAccess(vk); err != nil {
		t.Errorf("user should be allowed, got %v", err)
	}
	if IsAdmin(vk) {
		t.Error("expected IsAdmin=false for user role")
	}
}

func TestCheckAccess_ReadonlyForbidden(t *testing.T) {
	vk := &keys.VirtualKey{ID: "k3", Role: "readonly", Status: "active"}
	err := CheckAccess(vk)
	if err == nil {
		t.Fatal("readonly should return error")
	}
	if err != ErrReadonly {
		t.Errorf("expected ErrReadonly, got %v", err)
	}
}

func TestCheckAccess_MissingRoleDefaultsToUser(t *testing.T) {
	vk := &keys.VirtualKey{ID: "k4", Status: "active"}
	if err := CheckAccess(vk); err != nil {
		t.Errorf("empty role should default to user, got %v", err)
	}
	if EffectiveRole(vk) != RoleUser {
		t.Errorf("expected role 'user', got %q", EffectiveRole(vk))
	}
}

func TestCheckAccess_NilKey(t *testing.T) {
	if err := CheckAccess(nil); err != nil {
		t.Errorf("nil key should default to user, got %v", err)
	}
	if EffectiveRole(nil) != RoleUser {
		t.Errorf("expected role 'user' for nil key")
	}
}

func TestIsAdmin_NonAdmin(t *testing.T) {
	tests := []struct {
		role string
		want bool
	}{
		{"admin", true},
		{"user", false},
		{"readonly", false},
		{"", false},
		{"unknown", false},
	}
	for _, tt := range tests {
		vk := &keys.VirtualKey{Role: tt.role}
		if got := IsAdmin(vk); got != tt.want {
			t.Errorf("IsAdmin(role=%q) = %v, want %v", tt.role, got, tt.want)
		}
	}
}
