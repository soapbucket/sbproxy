// Package proxy will hold the extracted reverse-proxy action handler.
// For Phase 1, we register the existing config-based loader from internal/config.
// The full config/behavior separation happens incrementally in later phases.
package proxy

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the proxy action loader to the given Registry.
func Register(r *config.Registry) {
	r.RegisterAction(config.TypeProxy, config.LoadProxy)
}
