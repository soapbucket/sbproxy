// Package expression will hold the extracted expression policy handler.
// For Phase 1, we register the existing config-based loader from internal/config.
// The full config/behavior separation happens incrementally in later phases.
package expression

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the expression policy loader to the given Registry.
func Register(r *config.Registry) {
	r.RegisterPolicy(config.PolicyTypeExpression, config.NewExpressionPolicy)
}
