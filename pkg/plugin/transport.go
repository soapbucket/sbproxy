// transport.go defines the TransportFactory type for registering custom HTTP transports.
package plugin

import (
	"encoding/json"
	"net/http"
)

// TransportFactory is a constructor function that creates an [http.RoundTripper]
// from raw JSON configuration. Use this to register custom transports that control
// how outbound requests are sent to upstream targets. Examples include transports
// with mutual TLS, custom connection pooling, protocol adapters (e.g., HTTP/3),
// or request coalescing.
//
// Registered via [RegisterTransport] during init(). The name should match the
// "transport" field used in origin action configuration (e.g., "h2c", "mtls").
type TransportFactory func(cfg json.RawMessage) (http.RoundTripper, error)
