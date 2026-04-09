// Package httpsconnect will hold the extracted HTTPS CONNECT proxy action handler.
// For Phase 1, we register the existing config-based loader from internal/config.
// The full config/behavior separation happens incrementally in later phases.
package httpsconnect

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the https_proxy action loader to the given Registry.
func Register(r *config.Registry) {
	r.RegisterAction(config.TypeHTTPSProxy, config.LoadHTTPSProxy)
}
