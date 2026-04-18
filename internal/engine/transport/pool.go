// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"net"
	"net/http"
	"time"
)

// PoolConfig configures per-origin connection pooling.
type PoolConfig struct {
	MaxConnections int           `json:"max_connections" yaml:"max_connections"`
	MaxIdleConns   int           `json:"max_idle_conns" yaml:"max_idle_conns"`
	IdleTimeout    time.Duration `json:"idle_timeout" yaml:"idle_timeout"`
	MaxLifetime    time.Duration `json:"max_lifetime" yaml:"max_lifetime"`
}

// DefaultPoolConfig returns sensible defaults for connection pooling.
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxConnections: 100,
		MaxIdleConns:   50,
		IdleTimeout:    90 * time.Second,
		MaxLifetime:    0, // No max lifetime by default
	}
}

// NewTransportWithPool creates an http.Transport configured with pool settings.
// Zero-value fields in cfg are replaced with defaults from DefaultPoolConfig.
func NewTransportWithPool(cfg PoolConfig) *http.Transport {
	defaults := DefaultPoolConfig()

	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = defaults.MaxConnections
	}
	if cfg.MaxIdleConns <= 0 {
		cfg.MaxIdleConns = defaults.MaxIdleConns
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaults.IdleTimeout
	}

	// Ensure MaxIdleConns does not exceed MaxConnections
	if cfg.MaxIdleConns > cfg.MaxConnections {
		cfg.MaxIdleConns = cfg.MaxConnections
	}

	return &http.Transport{
		MaxConnsPerHost:     cfg.MaxConnections,
		MaxIdleConns:        cfg.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.MaxIdleConns,
		IdleConnTimeout:     cfg.IdleTimeout,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 0, // No timeout by default; callers set per-request deadlines
		ForceAttemptHTTP2:      true,
	}
}
