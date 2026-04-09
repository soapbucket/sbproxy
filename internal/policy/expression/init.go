// Package expression implements the CEL expression policy for sbproxy origins.
//
// Expression policies evaluate user-defined CEL (Common Expression Language)
// expressions against request attributes (headers, path, method, IP) to
// make allow/deny decisions. Expressions are compiled once at config load
// time and evaluated per-request with minimal overhead.
//
// Registration happens via [Register], which wires the expression policy
// loader into the config registry so that origins with policy type
// "expression" are handled by this package.
package expression

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the expression policy loader to the given Registry.
// After registration, any origin config with policy type "expression"
// will be deserialized and validated by the expression policy loader
// during config load.
func Register(r *config.Registry) {
	r.RegisterPolicy(config.PolicyTypeExpression, config.NewExpressionPolicy)
}
