// Package html will hold the extracted HTML transform handler.
// For Phase 1, we register the existing config-based loader from internal/config.
// The full config/behavior separation happens incrementally in later phases.
package html

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the HTML transform loader to the given Registry.
func Register(r *config.Registry) {
	r.RegisterTransform(config.TransformHTML, config.NewHTMLTransform)
}
