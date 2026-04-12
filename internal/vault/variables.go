// Package vault provides secret management, vault providers, and field-level
// secret resolution for proxy configurations.
package vault

import (
	"fmt"
	"regexp"
)

// reservedContextNames are top-level template context names that cannot be used as variable keys.
// Includes both new namespace names and legacy aliases (kept during migration).
var reservedContextNames = map[string]bool{
	// New 9-namespace model
	"origin":   true,
	"server":   true,
	"vars":     true,
	"features": true,
	"request":  true,
	"session":  true,
	"client":   true,
	"ctx":      true,
	"cache":    true,

	// Legacy aliases (kept during migration)
	"original":     true,
	"config":       true,
	"request_data": true,
	"secrets":      true,
	"session_data": true,
	"auth":         true,
	"auth_data":    true,
	"location":     true,
	"user_agent":   true,
	"fingerprint":  true,
	"var":          true,
	"env":          true,
	"feature":      true,
	"secret":       true,
}

// validKeyPattern matches valid variable key names: alphanumeric and underscores, starting with a letter or underscore
var validKeyPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// ValidateVariables validates the variables map keys
func ValidateVariables(variables map[string]any) error {
	for key := range variables {
		if !validKeyPattern.MatchString(key) {
			return fmt.Errorf("invalid variable key %q: must match [a-zA-Z_][a-zA-Z0-9_]*", key)
		}
		if reservedContextNames[key] {
			return fmt.Errorf("variable key %q is a reserved context name", key)
		}
	}
	return nil
}

