// Package css will hold the extracted CSS transform handler.
// For Phase 1, we register the existing config-based loader from internal/config.
// The full config/behavior separation happens incrementally in later phases.
package css

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the CSS transform loader to the given Registry.
func Register(r *config.Registry) {
	r.RegisterTransform(config.TransformCSS, config.NewCSSTransform)
}
