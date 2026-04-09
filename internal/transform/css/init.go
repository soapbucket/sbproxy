// Package css implements CSS response transforms for sbproxy origins.
//
// CSS transforms modify upstream CSS responses by rewriting URLs,
// adjusting paths, and applying find-and-replace rules before the
// response reaches the client.
//
// Registration happens via [Register], which wires the CSS transform
// loader into the config registry so that origins with transform type
// "css" are handled by this package.
package css

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the CSS transform loader to the given Registry.
// After registration, any origin config with transform type "css" will be
// deserialized and validated by the CSS transform loader during config load.
func Register(r *config.Registry) {
	r.RegisterTransform(config.TransformCSS, config.NewCSSTransform)
}
