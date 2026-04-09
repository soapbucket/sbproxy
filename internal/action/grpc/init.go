// Package grpc implements the gRPC proxy action for sbproxy.
//
// The gRPC action forwards gRPC (HTTP/2) requests to a configured upstream,
// supporting unary, server-streaming, client-streaming, and bidirectional
// streaming RPCs with header propagation and deadline forwarding.
//
// Registration happens via [Register], which wires the gRPC action loader
// into the config registry so that origins with action type "grpc" are
// handled by this package.
package grpc

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the gRPC action loader to the given Registry.
// After registration, any origin config with action type "grpc" will be
// deserialized and validated by the gRPC loader during config load.
func Register(r *config.Registry) {
	r.RegisterAction(config.TypeGRPC, config.NewGRPCAction)
}
