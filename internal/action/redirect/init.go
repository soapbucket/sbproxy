// Package redirect will hold the extracted redirect action handler.
// For Phase 1, we register the existing config-based loader from internal/config.
// The full config/behavior separation happens incrementally in later phases.
package redirect

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the redirect action loader to the given Registry.
func Register(r *config.Registry) {
	r.RegisterAction(config.TypeRedirect, config.LoadRedirectConfig)
}
