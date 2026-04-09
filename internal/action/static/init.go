// Package static implements the static content action for sbproxy.
//
// The static action serves fixed content (HTML, JSON, plain text) with a
// configurable status code and content type, without contacting any upstream.
// It is useful for maintenance pages, custom error responses, and mock APIs.
//
// Registration happens via [Register], which wires the static action loader
// into the config registry so that origins with action type "static" are
// handled by this package.
package static

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the static content action loader to the given Registry.
// After registration, any origin config with action type "static" will be
// deserialized and validated by the static loader during config load.
func Register(r *config.Registry) {
	r.RegisterAction(config.TypeStatic, config.LoadStaticConfig)
}
