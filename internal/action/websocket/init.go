// Package websocket will hold the extracted websocket action handler.
// For Phase 1, we register the existing config-based loader from internal/config.
// The full config/behavior separation happens incrementally in later phases.
package websocket

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the websocket action loader to the given Registry.
func Register(r *config.Registry) {
	r.RegisterAction(config.TypeWebSocket, config.NewWebSocketAction)
}
