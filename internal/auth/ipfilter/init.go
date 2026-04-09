// Package ipfilter will hold the extracted IP filtering handler.
// For Phase 1, we register the existing config-based loader from internal/config.
// Note: IP filtering is implemented as a policy type (PolicyTypeIPFiltering),
// not an auth type. This package wires the policy loader.
// The full config/behavior separation happens incrementally in later phases.
package ipfilter

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the IP filtering policy loader to the given Registry.
func Register(r *config.Registry) {
	r.RegisterPolicy(config.PolicyTypeIPFiltering, config.NewIPFilteringPolicy)
}
