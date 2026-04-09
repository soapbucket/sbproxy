// Package body implements HTTP body transforms for sbproxy origins.
//
// Body transforms apply find-and-replace, regex substitution, or
// template-based rewriting to request and response bodies as they pass
// through the proxy. This package structure is reserved for a dedicated
// body transform type; the current body modification logic lives in the
// request/response modifier layer.
//
// Register is a placeholder until the dedicated transform type is defined
// in the config layer.
package body

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register is a placeholder for future body transform registration.
// No dedicated body transform type exists in the config layer yet.
func Register(_ *config.Registry) {
	// TODO: Wire body transform loader once the transform type is defined.
}
