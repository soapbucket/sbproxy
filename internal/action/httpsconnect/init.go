// Package httpsconnect implements the HTTPS CONNECT tunnel action for sbproxy.
//
// The HTTPS CONNECT action handles HTTP CONNECT requests by establishing a
// TCP tunnel to the target host, enabling clients to send encrypted traffic
// through the proxy without TLS termination.
//
// Registration happens via [Register], which wires the HTTPS CONNECT action
// loader into the config registry so that origins with action type
// "https_proxy" are handled by this package.
package httpsconnect

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the HTTPS CONNECT action loader to the given Registry.
// After registration, any origin config with action type "https_proxy"
// will be deserialized and validated by the HTTPS CONNECT loader during
// config load.
func Register(r *config.Registry) {
	r.RegisterAction(config.TypeHTTPSProxy, config.LoadHTTPSProxy)
}
