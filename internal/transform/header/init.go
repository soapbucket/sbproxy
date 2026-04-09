// Package header will hold the extracted header transform handler.
// For Phase 1, we create the package structure. No config-based loader exists
// yet for a dedicated header transform type.
// The full implementation happens incrementally in later phases.
package header

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register is a placeholder for future header transform registration.
// No dedicated header transform type exists in the config layer yet.
func Register(_ *config.Registry) {
	// TODO: Wire header transform loader once the transform type is defined.
}
