// Package rbac provides role-based access control for AI inference endpoints.
package rbac

import (
	"fmt"

	"github.com/soapbucket/sbproxy/internal/ai/keys"
)

// Role constants for virtual key access levels.
const (
	RoleAdmin    = "admin"    // All models, no rate/budget limits enforced.
	RoleUser     = "user"     // Normal access with limits enforced.
	RoleReadonly = "readonly" // Read-only; inference requests return 403.
)

// ErrReadonly is returned when a readonly key attempts an inference request.
var ErrReadonly = fmt.Errorf("rbac: readonly keys cannot make inference requests")

// EffectiveRole returns the role for a virtual key, defaulting to "user"
// if no role is set.
func EffectiveRole(vk *keys.VirtualKey) string {
	if vk == nil || vk.Role == "" {
		return RoleUser
	}
	return vk.Role
}

// CheckAccess validates that the virtual key has sufficient permissions for
// inference. Returns nil for admin and user roles, ErrReadonly for readonly.
func CheckAccess(vk *keys.VirtualKey) error {
	role := EffectiveRole(vk)
	switch role {
	case RoleAdmin, RoleUser:
		return nil
	case RoleReadonly:
		return ErrReadonly
	default:
		// Unknown roles are treated as "user" (enforced).
		return nil
	}
}

// IsAdmin returns true if the key has the admin role, which bypasses
// rate limits and budget enforcement.
func IsAdmin(vk *keys.VirtualKey) bool {
	return EffectiveRole(vk) == RoleAdmin
}
