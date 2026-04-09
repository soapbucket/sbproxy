// Package body will hold the extracted body transform handler.
// For Phase 1, we create the package structure. No config-based loader exists
// yet for a dedicated body transform type.
// The full implementation happens incrementally in later phases.
package body

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register is a placeholder for future body transform registration.
// No dedicated body transform type exists in the config layer yet.
func Register(_ *config.Registry) {
	// TODO: Wire body transform loader once the transform type is defined.
}
