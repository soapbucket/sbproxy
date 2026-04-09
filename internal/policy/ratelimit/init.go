// Package ratelimit implements the rate limiting policy for sbproxy origins.
//
// Rate limiting enforces per-origin request quotas using configurable windows
// (requests per second/minute/hour), keyed by client IP, header value, or
// other identifiers. Clients that exceed the limit receive a 429 response
// with a Retry-After header.
//
// Registration happens via [Register], which wires the rate limit policy
// loader into the config registry so that origins with policy type
// "rate_limiting" are handled by this package.
package ratelimit

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the rate limiting policy loader to the given Registry.
// After registration, any origin config with policy type "rate_limiting"
// will be deserialized and validated by the rate limiter loader during
// config load.
func Register(r *config.Registry) {
	r.RegisterPolicy(config.PolicyTypeRateLimiting, config.NewRateLimitingPolicy)
}
