// Package static will hold the extracted static-content action handler.
// For Phase 1, we register the existing config-based loader from internal/config.
// The full config/behavior separation happens incrementally in later phases.
package static

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the static action loader to the given Registry.
func Register(r *config.Registry) {
	r.RegisterAction(config.TypeStatic, config.LoadStaticConfig)
}
