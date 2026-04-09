// Package loadbalancer implements the load balancer action for sbproxy.
//
// The load balancer action distributes incoming requests across multiple
// upstream origins using configurable strategies (round-robin, weighted,
// least-connections, random) with health checking and circuit breaking.
//
// Registration happens via [Register], which wires the load balancer
// action loader into the config registry so that origins with action type
// "load_balancer" are handled by this package.
package loadbalancer

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the load balancer action loader to the given Registry.
// After registration, any origin config with action type "load_balancer"
// will be deserialized and validated by the load balancer loader during
// config load.
func Register(r *config.Registry) {
	r.RegisterAction(config.TypeLoadBalancer, config.LoadLoadBalancerConfig)
}
