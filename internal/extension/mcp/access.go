// Package mcp implements the Model Context Protocol (MCP) for AI tool and resource integration.
package mcp

import (
	"fmt"
)

// ToolAccessConfig configures access control for a tool.
type ToolAccessConfig struct {
	AllowedRoles []string `json:"allowed_roles,omitempty"`
	AllowedKeys  []string `json:"allowed_keys,omitempty"` // Virtual key IDs
	DeniedRoles  []string `json:"denied_roles,omitempty"`
}

// AccessChecker validates tool access based on request context.
type AccessChecker struct {
	rules map[string]*ToolAccessConfig // toolName -> config
}

// NewAccessChecker creates a new AccessChecker with the given rules.
func NewAccessChecker(rules map[string]*ToolAccessConfig) *AccessChecker {
	if rules == nil {
		rules = make(map[string]*ToolAccessConfig)
	}
	return &AccessChecker{rules: rules}
}

// Check returns nil if access is allowed, error otherwise.
// Evaluation order: denied roles first, then allowed roles, then allowed keys.
// If no rules exist for a tool, access is allowed by default.
func (ac *AccessChecker) Check(toolName string, roles []string, keyID string) error {
	rule, ok := ac.rules[toolName]
	if !ok {
		return nil // No rules means open access
	}

	// Check denied roles first (explicit deny wins)
	if len(rule.DeniedRoles) > 0 {
		for _, denied := range rule.DeniedRoles {
			for _, role := range roles {
				if role == denied {
					return fmt.Errorf("access denied: role %q is denied for tool %q", role, toolName)
				}
			}
		}
	}

	// If both allowed_roles and allowed_keys are empty, allow all (no restrictions beyond denied)
	hasRoleRestriction := len(rule.AllowedRoles) > 0
	hasKeyRestriction := len(rule.AllowedKeys) > 0

	if !hasRoleRestriction && !hasKeyRestriction {
		return nil
	}

	// Check allowed roles
	if hasRoleRestriction {
		for _, allowed := range rule.AllowedRoles {
			for _, role := range roles {
				if role == allowed {
					return nil // Role match found
				}
			}
		}
	}

	// Check allowed keys
	if hasKeyRestriction && keyID != "" {
		for _, allowed := range rule.AllowedKeys {
			if keyID == allowed {
				return nil // Key match found
			}
		}
	}

	return fmt.Errorf("access denied: insufficient permissions for tool %q", toolName)
}

// HasRules returns true if rules are configured for the given tool.
func (ac *AccessChecker) HasRules(toolName string) bool {
	_, ok := ac.rules[toolName]
	return ok
}
