// Package proxy implements the reverse proxy action for sbproxy.
//
// The proxy action forwards incoming HTTP requests to a configured upstream
// URL, supporting request rewriting, response modification, streaming, and
// connection pooling.
//
// Registration happens via [Register], which wires the proxy action loader
// into the config registry so that origins with action type "proxy" are
// handled by this package.
package proxy

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the proxy action loader to the given Registry.
// After registration, any origin config with action type "proxy" will be
// deserialized and validated by the proxy loader during config load.
func Register(r *config.Registry) {
	r.RegisterAction(config.TypeProxy, config.LoadProxy)
}
