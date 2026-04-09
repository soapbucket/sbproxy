// Package apikey implements API key authentication for sbproxy origins.
//
// Incoming requests are validated against a configured set of API keys,
// which may be supplied via headers, query parameters, or bearer tokens.
// Unauthorized requests receive a 401 response before reaching the upstream.
//
// Registration happens via [Register], which wires the API key auth loader
// into the config registry so that origins with auth type "api_key" are
// handled by this package.
package apikey

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the API key auth loader to the given Registry.
// After registration, any origin config with auth type "api_key" will be
// deserialized and validated by the API key auth loader during config load.
func Register(r *config.Registry) {
	r.RegisterAuth(config.AuthTypeAPIKey, config.NewAPIKeyAuthConfig)
}
