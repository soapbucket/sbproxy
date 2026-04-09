// Package websocket implements the WebSocket proxy action for sbproxy.
//
// The WebSocket action upgrades HTTP connections to WebSocket and proxies
// bidirectional frames between the client and the configured upstream,
// supporting ping/pong, close handshakes, and per-message compression.
//
// Registration happens via [Register], which wires the WebSocket action
// loader into the config registry so that origins with action type
// "websocket" are handled by this package.
package websocket

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the WebSocket action loader to the given Registry.
// After registration, any origin config with action type "websocket"
// will be deserialized and validated by the WebSocket loader during
// config load.
func Register(r *config.Registry) {
	r.RegisterAction(config.TypeWebSocket, config.NewWebSocketAction)
}
