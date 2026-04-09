// Package basic implements HTTP Basic authentication for sbproxy origins.
//
// Incoming requests must include a valid username:password pair in the
// Authorization header. Credentials are validated using constant-time
// comparison to prevent timing attacks.
//
// Registration happens via [Register], which wires the basic auth loader
// into the config registry so that origins with auth type "basic_auth"
// are handled by this package.
package basic

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the basic auth loader to the given Registry.
// After registration, any origin config with auth type "basic_auth" will be
// deserialized and validated by the basic auth loader during config load.
func Register(r *config.Registry) {
	r.RegisterAuth(config.AuthTypeBasicAuth, config.NewBasicAuthConfig)
}
