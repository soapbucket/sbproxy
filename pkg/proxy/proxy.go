// Package proxy provides the public entry points for embedding sbproxy in another
// Go program. Use [New] to create a proxy instance for inspection or testing, or
// [Run] to start a fully configured proxy that blocks until shutdown.
//
// Optional features (metrics, event bus, custom storage) are injected via [Option]
// functions, keeping this package free of optional-dependency imports.
package proxy

import "context"

// Config holds the startup configuration for the proxy server. These fields map
// directly to CLI flags and environment variables accepted by the sbproxy binary.
type Config struct {
	// ConfigDir is the directory containing origin configuration files. The proxy
	// watches this directory for changes and reloads automatically.
	ConfigDir string

	// ConfigFile is the path to a single configuration file (e.g., sb.yml). When set,
	// ConfigDir is ignored and only this file is loaded.
	ConfigFile string

	// LogLevel controls the global log verbosity. Accepted values are "debug", "info",
	// "warn", and "error".
	LogLevel string

	// RequestLogLevel controls the verbosity of per-request access logs, separate
	// from the global LogLevel. Set to "none" to disable request logging entirely.
	RequestLogLevel string

	// GraceTime is the number of seconds to wait for in-flight requests to complete
	// during graceful shutdown before forcefully closing connections.
	GraceTime int

	// DisableHostFilter, when true, skips hostname validation on incoming requests.
	// This is useful during development when requests may arrive on localhost or
	// non-matching hostnames. Do not enable in production.
	DisableHostFilter bool
}

// Option is a function that configures optional features on a [Proxy] instance.
// Option constructors can be provided for capabilities like Prometheus metrics,
// Redis-backed event buses, and external configuration stores. Options are
// applied in order during [New], so later options can override earlier ones.
type Option func(*Proxy)

// Proxy is the core proxy engine. It holds the startup configuration and any
// registered options. Use [New] to create an instance or [Run] for a blocking
// start-to-shutdown lifecycle.
type Proxy struct {
	config  Config
	options []Option
}

// New creates a Proxy instance with the given configuration and options. The proxy
// is not started until [Run] is called. This is useful for inspecting the configuration
// or wiring the proxy into a test harness.
func New(cfg Config, opts ...Option) *Proxy {
	p := &Proxy{config: cfg, options: opts}
	return p
}

// Run creates a proxy with the given configuration and options, starts listening for
// requests, and blocks until the context is cancelled or a shutdown signal is received.
// This is the primary entry point for embedding sbproxy in another Go program.
//
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//	if err := proxy.Run(ctx, cfg); err != nil {
//	    log.Fatal(err)
//	}
func Run(ctx context.Context, cfg Config, opts ...Option) error {
	// TODO: Wire to internal/service or internal/cli
	// This is a placeholder that will be connected in a later phase.
	return nil
}
