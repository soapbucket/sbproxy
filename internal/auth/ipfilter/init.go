// Package ipfilter implements IP-based access control for sbproxy origins.
//
// Requests are allowed or denied based on the client IP address matched
// against configurable whitelist and blacklist CIDR ranges, with support
// for trusted proxy headers (X-Forwarded-For, X-Real-IP) and IPv6.
//
// Note: IP filtering is registered as a policy type (PolicyTypeIPFiltering)
// rather than an auth type, because it operates on network-layer identity
// rather than user credentials.
//
// Registration happens via [Register], which wires the IP filter policy
// loader into the config registry.
package ipfilter

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the IP filtering policy loader to the given Registry.
// After registration, any origin config with policy type "ip_filtering"
// will be deserialized and validated by the IP filter loader during
// config load.
func Register(r *config.Registry) {
	r.RegisterPolicy(config.PolicyTypeIPFiltering, config.NewIPFilteringPolicy)
}
