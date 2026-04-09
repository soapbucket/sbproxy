// Package header implements HTTP header transforms for sbproxy origins.
//
// Header transforms add, remove, or rewrite HTTP headers on requests
// and responses as they pass through the proxy. This package structure
// is reserved for a dedicated header transform type; the current header
// modification logic lives in the request/response modifier layer.
//
// Register is a placeholder until the dedicated transform type is defined
// in the config layer.
package header

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register is a placeholder for future header transform registration.
// No dedicated header transform type exists in the config layer yet.
func Register(_ *config.Registry) {
	// TODO: Wire header transform loader once the transform type is defined.
}
