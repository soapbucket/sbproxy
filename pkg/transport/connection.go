// Package transport provides public connection configuration types for upstream transports.
//
// ConnectionConfig is the public counterpart of internal/config.BaseConnection.
// It holds all connection-level settings needed to create an http.RoundTripper.
// Use time.Duration for all duration fields (no internal dependencies).
//
// The actual transport factory is in internal/engine/transport.NewTransportFromConfig.
// Action modules in internal/modules/action/{name}/ use this package to declare
// their config structs without importing internal/config.
package transport

import "time"

// CertificatePinningConfig configures TLS certificate pinning for upstream connections.
type CertificatePinningConfig struct {
	// Enabled activates certificate pinning for this connection.
	Enabled bool `json:"enabled"`
	// PinSHA256 is the primary pin: a base64-encoded SHA-256 hash of the SPKI.
	PinSHA256 string `json:"pin_sha256"`
	// BackupPins are additional pins used during certificate rotation.
	BackupPins []string `json:"backup_pins"`
	// PinExpiry is an optional RFC3339 date after which the pin is considered stale.
	PinExpiry string `json:"pin_expiry,omitempty"`
}

// HTTP2CoalescingOverride holds per-origin overrides for HTTP/2 connection coalescing.
// Zero values mean "inherit from global config".
type HTTP2CoalescingOverride struct {
	Disabled                 bool          `json:"disabled,omitempty"`
	MaxIdleConnsPerHost      int           `json:"max_idle_conns_per_host,omitempty"`
	IdleConnTimeout          time.Duration `json:"idle_conn_timeout,omitempty"`
	MaxConnLifetime          time.Duration `json:"max_conn_lifetime,omitempty"`
	AllowIPBasedCoalescing   bool          `json:"allow_ip_based_coalescing,omitempty"`
	AllowCertBasedCoalescing bool          `json:"allow_cert_based_coalescing,omitempty"`
	StrictCertValidation     bool          `json:"strict_cert_validation,omitempty"`
}

// RequestCoalescingOverride holds per-origin overrides for request coalescing.
type RequestCoalescingOverride struct {
	Enabled         bool          `json:"enabled,omitempty"`
	MaxInflight     int           `json:"max_inflight,omitempty"`
	CoalesceWindow  time.Duration `json:"coalesce_window,omitempty"`
	MaxWaiters      int           `json:"max_waiters,omitempty"`
	CleanupInterval time.Duration `json:"cleanup_interval,omitempty"`
	KeyStrategy     string        `json:"key_strategy,omitempty"`
}

// RetryConfig configures automatic retry for upstream requests.
type RetryConfig struct {
	Enabled         bool          `json:"enabled"`
	MaxRetries      int           `json:"max_retries,omitempty"`
	InitialDelay    time.Duration `json:"initial_delay,omitempty"`
	MaxDelay        time.Duration `json:"max_delay,omitempty"`
	Multiplier      float64       `json:"multiplier,omitempty"`
	Jitter          float64       `json:"jitter,omitempty"`
	RetryableStatus []int         `json:"retryable_status,omitempty"`
}

// HedgingConfig configures speculative request hedging.
type HedgingConfig struct {
	Enabled             bool          `json:"enabled"`
	Delay               time.Duration `json:"delay,omitempty"`
	MaxHedges           int           `json:"max_hedges,omitempty"`
	PercentileThreshold float64       `json:"percentile_threshold,omitempty"`
	Methods             []string      `json:"methods,omitempty"`
	MaxCostRatio        float64       `json:"max_cost_ratio,omitempty"`
}

// HealthCheckConfig configures transport-level health checking for a backend.
type HealthCheckConfig struct {
	Enabled            bool          `json:"enabled"`
	Type               string        `json:"type,omitempty"`
	Endpoint           string        `json:"endpoint,omitempty"`
	Host               string        `json:"host,omitempty"`
	Interval           time.Duration `json:"interval,omitempty"`
	Timeout            time.Duration `json:"timeout,omitempty"`
	HealthyThreshold   int           `json:"healthy_threshold,omitempty"`
	UnhealthyThreshold int           `json:"unhealthy_threshold,omitempty"`
	ExpectedStatus     int           `json:"expected_status,omitempty"`
	ExpectedBody       string        `json:"expected_body,omitempty"`
}

// CircuitBreakerConfig configures a per-origin circuit breaker for the transport.
type CircuitBreakerConfig struct {
	Enabled          bool          `json:"enabled"`
	FailureThreshold int           `json:"failure_threshold,omitempty"`
	SuccessThreshold int           `json:"success_threshold,omitempty"`
	Timeout          time.Duration `json:"timeout,omitempty"`
}

// TransportWrappersConfig groups optional transport middleware (retry, hedging, health check, circuit breaker).
type TransportWrappersConfig struct {
	Retry          *RetryConfig          `json:"retry,omitempty"`
	Hedging        *HedgingConfig        `json:"hedging,omitempty"`
	HealthCheck    *HealthCheckConfig    `json:"health_check,omitempty"`
	CircuitBreaker *CircuitBreakerConfig `json:"circuit_breaker,omitempty"`
}

// ConnectionConfig defines all connection-level settings for creating an upstream
// http.RoundTripper. It is the public equivalent of internal/config.BaseConnection,
// using standard time.Duration instead of the internal reqctx.Duration type.
//
// All duration fields default to zero, which causes the factory to apply
// production-sensible defaults (10s dial, 10s TLS handshake, 30s idle, 30s timeout).
type ConnectionConfig struct {
	// TLS / security
	SkipTLSVerifyHost  bool                      `json:"skip_tls_verify_host,omitempty"`
	MinTLSVersion      string                    `json:"min_tls_version,omitempty"`
	CertificatePinning *CertificatePinningConfig `json:"certificate_pinning,omitempty"`

	// Protocol selection
	HTTP11Only  bool `json:"http11_only,omitempty"`
	EnableHTTP3 bool `json:"enable_http3,omitempty"`

	// Redirect handling
	DisableFollowRedirects bool `json:"disable_follow_redirects,omitempty"`
	MaxRedirects           int  `json:"max_redirects,omitempty"`

	// Compression
	DisableCompression bool `json:"disable_compression,omitempty"`

	// Timeouts
	Timeout             time.Duration `json:"timeout,omitempty"`
	Delay               time.Duration `json:"delay,omitempty"`
	DialTimeout         time.Duration `json:"dial_timeout,omitempty"`
	TLSHandshakeTimeout time.Duration `json:"tls_handshake_timeout,omitempty"`
	IdleConnTimeout     time.Duration `json:"idle_conn_timeout,omitempty"`
	KeepAlive           time.Duration `json:"keep_alive,omitempty"`
	FlushInterval       time.Duration `json:"flush_interval,omitempty"`

	ResponseHeaderTimeout time.Duration `json:"response_header_timeout,omitempty"`
	ExpectContinueTimeout time.Duration `json:"expect_continue_timeout,omitempty"`

	// Connection pool limits
	MaxConnections      int `json:"max_connections,omitempty"`
	MaxIdleConns        int `json:"max_idle_conns,omitempty"`
	MaxIdleConnsPerHost int `json:"max_idle_conns_per_host,omitempty"`
	MaxConnsPerHost     int `json:"max_conns_per_host,omitempty"`

	// Buffer sizes
	WriteBufferSize int `json:"write_buffer_size,omitempty"`
	ReadBufferSize  int `json:"read_buffer_size,omitempty"`

	// Rate / burst limits
	RateLimit  int `json:"rate_limit,omitempty"`
	BurstLimit int `json:"burst_limit,omitempty"`

	// Mutual TLS - file paths
	MTLSClientCertFile string `json:"mtls_client_cert_file,omitempty"`
	MTLSClientKeyFile  string `json:"mtls_client_key_file,omitempty"`
	MTLSCACertFile     string `json:"mtls_ca_cert_file,omitempty"`
	// Mutual TLS - base64-encoded PEM data
	MTLSClientCertData string `json:"mtls_client_cert_data,omitempty"`
	MTLSClientKeyData  string `json:"mtls_client_key_data,omitempty"`
	MTLSCACertData     string `json:"mtls_ca_cert_data,omitempty"`

	// HTTP/2 coalescing (per-origin override; nil = use global defaults)
	HTTP2Coalescing *HTTP2CoalescingOverride `json:"http2_coalescing,omitempty"`

	// Request coalescing (per-origin override; nil = use global defaults)
	RequestCoalescing *RequestCoalescingOverride `json:"request_coalescing,omitempty"`

	// Transport wrappers (retry, hedging, health check)
	TransportWrappers *TransportWrappersConfig `json:"transport_wrappers,omitempty"`
}
