// Package json implements JSON response transforms for sbproxy origins.
//
// JSON transforms modify upstream JSON responses by projecting specific
// fields, renaming keys, or injecting computed values before the response
// reaches the client.
//
// Registration happens via [Register], which wires the JSON transform
// loader into the config registry so that origins with transform type
// "json" are handled by this package.
package json

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the JSON transform loader to the given Registry.
// After registration, any origin config with transform type "json" will be
// deserialized and validated by the JSON transform loader during config load.
func Register(r *config.Registry) {
	r.RegisterTransform(config.TransformJSON, config.NewJSONTransform)
}
