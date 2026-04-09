// Package basic will hold the extracted basic authentication handler.
// For Phase 1, we register the existing config-based loader from internal/config.
// The full config/behavior separation happens incrementally in later phases.
package basic

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the basic auth loader to the given Registry.
func Register(r *config.Registry) {
	r.RegisterAuth(config.AuthTypeBasicAuth, config.NewBasicAuthConfig)
}
