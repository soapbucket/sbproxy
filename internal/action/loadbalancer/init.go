// Package loadbalancer will hold the extracted load-balancer action handler.
// For Phase 1, we register the existing config-based loader from internal/config.
// The full config/behavior separation happens incrementally in later phases.
package loadbalancer

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the loadbalancer action loader to the given Registry.
func Register(r *config.Registry) {
	r.RegisterAction(config.TypeLoadBalancer, config.LoadLoadBalancerConfig)
}
