// Package echo implements the echo action for sbproxy.
//
// The echo action returns a static response body and status code without
// contacting any upstream server. It is useful for health checks, testing,
// and returning fixed content from the proxy layer.
//
// Registration happens via [Register], which wires the echo action loader
// into the config registry so that origins with action type "echo" are
// handled by this package.
package echo

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the echo action loader to the given Registry.
// After registration, any origin config with action type "echo" will be
// deserialized and validated by the echo loader during config load.
func Register(r *config.Registry) {
	r.RegisterAction(config.TypeEcho, config.LoadEchoConfig)
}
