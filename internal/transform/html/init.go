// Package html implements HTML response transforms for sbproxy origins.
//
// HTML transforms modify upstream HTML responses by rewriting URLs,
// injecting scripts or stylesheets, and stripping or replacing DOM
// elements before the response reaches the client.
//
// Registration happens via [Register], which wires the HTML transform
// loader into the config registry so that origins with transform type
// "html" are handled by this package.
package html

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the HTML transform loader to the given Registry.
// After registration, any origin config with transform type "html" will be
// deserialized and validated by the HTML transform loader during config load.
func Register(r *config.Registry) {
	r.RegisterTransform(config.TransformHTML, config.NewHTMLTransform)
}
