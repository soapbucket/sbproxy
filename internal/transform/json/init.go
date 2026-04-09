// Package json will hold the extracted JSON transform handler.
// For Phase 1, we register the existing config-based loader from internal/config.
// The full config/behavior separation happens incrementally in later phases.
package json

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the JSON transform loader to the given Registry.
func Register(r *config.Registry) {
	r.RegisterTransform(config.TransformJSON, config.NewJSONTransform)
}
