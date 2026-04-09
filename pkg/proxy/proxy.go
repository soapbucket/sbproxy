package proxy

import "context"

// Config holds proxy startup options.
type Config struct {
	ConfigDir         string
	ConfigFile        string
	LogLevel          string
	RequestLogLevel   string
	GraceTime         int
	DisableHostFilter bool
}

// Option configures optional proxy features.
type Option func(*Proxy)

// Proxy is the core proxy engine.
type Proxy struct {
	config  Config
	options []Option
}

// New creates a proxy instance.
func New(cfg Config, opts ...Option) *Proxy {
	p := &Proxy{config: cfg, options: opts}
	return p
}

// Run starts the proxy and blocks until shutdown or context cancellation.
func Run(ctx context.Context, cfg Config, opts ...Option) error {
	// TODO: Wire to internal/service or internal/cli
	// This is a placeholder that will be connected in a later phase.
	return nil
}
