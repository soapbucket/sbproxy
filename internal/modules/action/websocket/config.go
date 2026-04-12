// Package websocket defines config types for the websocket action module.
//
// All struct and JSON field names match the canonical definitions in
// internal/config/types.go so that existing YAML/JSON configurations parse
// identically. This package has zero imports from internal/config.
package websocket

import (
	"encoding/json"
	"fmt"
	"time"
)

// Duration is a JSON-decodable time.Duration using a string like "10s", "1m".
type Duration struct {
	time.Duration
}

// MarshalJSON encodes the duration as a JSON string like "10s".
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Duration.String())
}

// UnmarshalJSON decodes a duration from a JSON string or number (nanoseconds).
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		dur, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("websocket: parse duration %q: %w", s, err)
		}
		d.Duration = dur
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("websocket: decode duration: %w", err)
	}
	d.Duration = time.Duration(n)
	return nil
}

// Config is the top-level websocket action configuration.
// JSON tags must stay in sync with internal/config.WebSocketConfig.
type Config struct {
	Type string `json:"type"` // always "websocket"

	URL           string `json:"url"`                       // Backend WebSocket URL (ws:// or wss://)
	StripBasePath bool   `json:"strip_base_path,omitempty"` // Preserve client path on the backend URL
	PreserveQuery bool   `json:"preserve_query,omitempty"`  // Preserve client query string
	Provider      string `json:"provider,omitempty"`        // Optional provider hint (e.g. "openai")

	PingInterval     Duration `json:"ping_interval,omitempty"`     // Send ping frames (default: 0 = disabled)
	PongTimeout      Duration `json:"pong_timeout,omitempty"`      // Wait for pong response (default: 10s)
	IdleTimeout      Duration `json:"idle_timeout,omitempty"`      // Close connections after read inactivity
	HandshakeTimeout Duration `json:"handshake_timeout,omitempty"` // WebSocket handshake timeout (default: 10s)

	ReadBufferSize    int  `json:"read_buffer_size,omitempty"`   // Buffer size for reads (default: 4096)
	WriteBufferSize   int  `json:"write_buffer_size,omitempty"`  // Buffer size for writes (default: 4096)
	MaxFrameSize      int  `json:"max_frame_size,omitempty"`     // Maximum size of a single message payload
	EnableCompression bool `json:"enable_compression,omitempty"` // Enable per-message compression

	Subprotocols   []string `json:"subprotocols,omitempty"`    // Supported subprotocols
	AllowedOrigins []string `json:"allowed_origins,omitempty"` // CORS origins (empty = all)
	CheckOrigin    bool     `json:"check_origin,omitempty"`    // Enable origin checking

	// TLS
	SkipTLSVerifyHost bool `json:"skip_tls_verify_host,omitempty"` // Disable TLS verification (insecure)

	// Connection pool settings (deferred - not used in extracted module yet)
	DisablePool              bool     `json:"disable_pool,omitempty"`
	PoolMaxConnections       int      `json:"pool_max_connections,omitempty"`
	PoolMaxIdleConnections   int      `json:"pool_max_idle_connections,omitempty"`
	PoolMaxLifetime          Duration `json:"pool_max_lifetime,omitempty"`
	PoolMaxIdleTime          Duration `json:"pool_max_idle_time,omitempty"`
	DisablePoolAutoReconnect bool     `json:"disable_pool_auto_reconnect,omitempty"`
	PoolReconnectDelay       Duration `json:"pool_reconnect_delay,omitempty"`
	PoolMaxReconnectAttempts int      `json:"pool_max_reconnect_attempts,omitempty"`
}
