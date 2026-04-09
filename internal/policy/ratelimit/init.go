// Package ratelimit will hold the extracted rate limiting policy handler.
// For Phase 1, we register the existing config-based loader from internal/config.
// The full config/behavior separation happens incrementally in later phases.
package ratelimit

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the rate limiting policy loader to the given Registry.
func Register(r *config.Registry) {
	r.RegisterPolicy(config.PolicyTypeRateLimiting, config.NewRateLimitingPolicy)
}
