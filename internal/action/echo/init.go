// Package echo will hold the extracted echo action handler.
// For Phase 1, we register the existing config-based loader from internal/config.
// The full config/behavior separation happens incrementally in later phases.
package echo

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the echo action loader to the given Registry.
func Register(r *config.Registry) {
	r.RegisterAction(config.TypeEcho, config.LoadEchoConfig)
}
