// Package apikey will hold the extracted API key authentication handler.
// For Phase 1, we register the existing config-based loader from internal/config.
// The full config/behavior separation happens incrementally in later phases.
package apikey

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the API key auth loader to the given Registry.
func Register(r *config.Registry) {
	r.RegisterAuth(config.AuthTypeAPIKey, config.NewAPIKeyAuthConfig)
}
