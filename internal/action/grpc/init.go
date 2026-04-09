// Package grpc will hold the extracted gRPC action handler.
// For Phase 1, we register the existing config-based loader from internal/config.
// The full config/behavior separation happens incrementally in later phases.
package grpc

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the grpc action loader to the given Registry.
func Register(r *config.Registry) {
	r.RegisterAction(config.TypeGRPC, config.NewGRPCAction)
}
