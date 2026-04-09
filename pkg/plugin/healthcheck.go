package plugin

import (
	"context"
	"encoding/json"
)

// HealthChecker is the interface for health check plugins. Health checkers run
// periodic probes against upstream targets to determine their availability.
// Built-in types include HTTP (GET/HEAD with status check) and TCP (connection
// dial). Custom health checkers can implement application-specific protocols
// like gRPC health checks or database pings.
//
// Implementations must be safe for concurrent use and should respect context
// cancellation for clean shutdown.
type HealthChecker interface {
	// Type returns the health check type name as it appears in configuration
	// (e.g., "http", "tcp", "grpc").
	Type() string

	// Check performs a single health probe and returns nil if the target is
	// healthy, or an error describing why the check failed. Implementations
	// should respect context deadlines and cancellation.
	Check(ctx context.Context) error

	// Close releases any resources held by the health checker (open connections,
	// goroutines, etc.). Called when the origin is removed or the proxy shuts down.
	Close() error
}

// HealthCheckerFactory is a constructor function that creates a HealthChecker from
// raw JSON configuration and a target URL. Registered via [RegisterHealthChecker]
// during init().
type HealthCheckerFactory func(targetURL string, cfg json.RawMessage) (HealthChecker, error)
