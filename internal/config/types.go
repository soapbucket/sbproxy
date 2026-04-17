// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync/atomic"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai"
	"github.com/soapbucket/sbproxy/internal/middleware/callback"
	"github.com/soapbucket/sbproxy/internal/middleware/csp"
	"github.com/soapbucket/sbproxy/internal/middleware/hsts"
	"github.com/soapbucket/sbproxy/internal/middleware/httpsig"
	"github.com/soapbucket/sbproxy/internal/middleware/modifier"
	"github.com/soapbucket/sbproxy/internal/middleware/rule"
	"github.com/soapbucket/sbproxy/internal/security/certpin"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/transformer"
)

// SessionConfig holds configuration for session.
type SessionConfig struct {
	Disabled bool `sb_flag:"disabled" json:"disabled,omitempty"`

	CookieName      string `json:"cookie_name,omitempty"`
	MaxAge          int    `json:"max_age,omitempty"`
	SameSite        string `json:"same_site,omitempty"`
	DisableHttpOnly bool   `json:"disable_http_only,omitempty"` // If true, cookie HttpOnly flag is set to false (default: false, so HttpOnly is true by default)
	AllowNonSSL     bool   `json:"allow_non_ssl,omitempty"`     // Allow sessions over HTTP (non-SSL) connections. If true and request is not TLS, cookie Secure flag is set to false.

	// Cookie jar configuration for storing proxied backend cookies
	EnableCookieJar bool             `sb_flag:"enable_cookie_jar" json:"enable_cookie_jar,omitempty"`
	CookieJarConfig *CookieJarConfig `json:"cookie_jar_config,omitempty"`

	// callbacks are executed and stored in the session data object
	OnSessionStart callback.Callbacks `json:"on_session_start,omitempty"`
}

// CookieJarConfig configures the session-based cookie jar
type CookieJarConfig struct {
	MaxCookies           int  `json:"max_cookies,omitempty"`             // Maximum number of cookies to store per session (default: 100, max: 500)
	MaxCookieSize        int  `json:"max_cookie_size,omitempty"`         // Maximum size of a single cookie value in bytes (default: 4096, max: 16384)
	StoreSecureOnly      bool `json:"store_secure_only,omitempty"`       // Only store cookies with Secure flag set (default: false)
	DisableStoreHttpOnly bool `json:"disable_store_http_only,omitempty"` // If true, do not store cookies with HttpOnly flag (default: false, so HttpOnly cookies are stored)
}

// APIConfig holds configuration for api.
type APIConfig struct {
	EnableAPI  bool   `sb_flag:"enable_api" json:"enable_api,omitempty"`
	AltAPIPath string `json:"alt_api_path,omitempty"`
	APIBearer  string `json:"api_bearer,omitempty" secret:"true"`
}

// BaseAuthConfig holds configuration for base auth.
type BaseAuthConfig struct {
	AuthType string `json:"type"`
	Disabled bool   `json:"disabled,omitempty"`

	AuthenticationCallback *callback.Callback `json:"authentication_callback,omitempty"`

	handler func(http.Handler) http.Handler `json:"-"`
	cfg     *Config                         `json:"-"`
}

// Roles represents a roles.
type Roles struct {
	Required []string `json:"required,omitempty"`
	Optional []string `json:"optional,omitempty"`
}

// Action represents a action.
type Action json.RawMessage

// BaseAction represents a base action.
type BaseAction struct {
	ActionType string `json:"type"`

	tr  http.RoundTripper `json:"-"`
	cfg *Config           `json:"-"`
}

// BaseConnection represents connection-level configuration
type BaseConnection struct {
	BaseAction

	DisableFollowRedirects bool   `sb_flag:"disable_follow_redirects" json:"disable_follow_redirects,omitempty"`
	DisableCompression     bool   `sb_flag:"disable_compression" json:"disable_compression,omitempty"`
	SkipTLSVerifyHost      bool   `sb_flag:"skip_tls_verify_host" json:"skip_tls_verify_host,omitempty"`
	MinTLSVersion          string `json:"min_tls_version,omitempty"`                       // Minimum TLS version for outbound connections ("1.2" or "1.3")
	HTTP11Only             bool   `sb_flag:"http11_only" json:"http11_only,omitempty"`     // Force HTTP/1.1 (disables HTTP/2 and HTTP/3)
	MaxRedirects           int    `json:"max_redirects,omitempty" validate:"max_value=20"` // Maximum redirects to follow (max: 20)
	EnableHTTP3            bool   `sb_flag:"enable_http3" json:"enable_http3,omitempty"`

	FlushInterval       reqctx.Duration `json:"flush_interval,omitempty" validate:"max_value=1m"`
	IdleConnTimeout     reqctx.Duration `json:"idle_conn_timeout,omitempty" validate:"max_value=1m,default_value=60s"`
	TLSHandshakeTimeout reqctx.Duration `json:"tls_handshake_timeout,omitempty" validate:"max_value=1m,default_value=10s"`
	DialTimeout         reqctx.Duration `json:"dial_timeout,omitempty" validate:"max_value=1m,default_value=10s"`
	KeepAlive           reqctx.Duration `json:"keep_alive,omitempty" validate:"max_value=1m,default_value=30s"`

	MaxConnections int             `json:"max_connections,omitempty" validate:"max_value=10000"` // Maximum concurrent connections (default: unlimited, max: 10,000)
	Timeout        reqctx.Duration `json:"timeout,omitempty" validate:"max_value=1m,default_value=30s"`
	Delay          reqctx.Duration `json:"delay,omitempty" validate:"max_value=1m"`

	RateLimit  int `json:"rate_limit,omitempty" validate:"max_value=1000000"` // Requests per second (max: 1,000,000)
	BurstLimit int `json:"burst_limit,omitempty" validate:"max_value=100000"` // Burst limit (max: 100,000)

	// Certificate pinning configuration (security enhancement)
	CertificatePinning *certpin.CertificatePinningConfig `json:"certificate_pinning,omitempty"`

	// Mutual TLS (mTLS) configuration for backend connections
	// Client certificate and key files for mTLS authentication
	MTLSClientCertFile string `json:"mtls_client_cert_file,omitempty"`              // Path to client certificate file
	MTLSClientKeyFile  string `json:"mtls_client_key_file,omitempty" secret:"true"` // Path to client private key file
	MTLSCACertFile     string `json:"mtls_ca_cert_file,omitempty"`                  // Optional: Path to CA certificate file for server verification
	// Base64-encoded certificate data (alternative to file paths)
	MTLSClientCertData string `json:"mtls_client_cert_data,omitempty"`              // Base64-encoded client certificate
	MTLSClientKeyData  string `json:"mtls_client_key_data,omitempty" secret:"true"` // Base64-encoded client private key
	MTLSCACertData     string `json:"mtls_ca_cert_data,omitempty"`                  // Optional: Base64-encoded CA certificate

	// Legacy buffer size fields (deprecated - use transport_wrappers instead)
	// Optimized default: 64KB per OPTIMIZATIONS.md #16
	WriteBufferSize int `json:"write_buffer_size,omitempty" validate:"max_value=10MB,default_value=64KB"`
	ReadBufferSize  int `json:"read_buffer_size,omitempty" validate:"max_value=10MB,default_value=64KB"`

	MaxIdleConns        int `json:"max_idle_conns,omitempty" validate:"max_value=5000"`         // Maximum idle connections across all hosts (max: 5,000)
	MaxIdleConnsPerHost int `json:"max_idle_conns_per_host,omitempty" validate:"max_value=500"` // Maximum idle connections per host (max: 500)
	MaxConnsPerHost     int `json:"max_conns_per_host,omitempty" validate:"max_value=5000"`     // Maximum connections per host (max: 5,000)

	// HTTP/2 connection coalescing configuration (per OPTIMIZATIONS.md #14)
	// Optional per-origin override, inherits from global config if not set
	HTTP2Coalescing *HTTP2CoalescingConfig `json:"http2_coalescing,omitempty"`

	// Request coalescing configuration (per OPTIMIZATIONS.md #10)
	// Optional per-origin override, inherits from global config if not set
	RequestCoalescing *RequestCoalescingConfig `json:"request_coalescing,omitempty"`

	// Transport wrappers configuration (new unified approach)
	// Note: Transport wrappers are not yet fully implemented
	// The fingerprint cacher is implemented as a Transform instead
	TransportWrappers     *TransportWrapperConfig `json:"transport_wrappers,omitempty"`
	ResponseHeaderTimeout reqctx.Duration         `json:"response_header_timeout,omitempty" validate:"max_value=1m,default_value=30s"`
	ExpectContinueTimeout reqctx.Duration         `json:"expect_continue_timeout,omitempty" validate:"max_value=1m,default_value=1s"`
}

// HTTP2CoalescingConfig represents HTTP/2 connection coalescing configuration
// Used for per-origin overrides (inherits from global config if not set)
type HTTP2CoalescingConfig struct {
	Disabled                 bool            `json:"disabled,omitempty"`                                                     // Disable connection coalescing (optional, inherits from global, default: false meaning enabled)
	MaxIdleConnsPerHost      int             `json:"max_idle_conns_per_host,omitempty" validate:"min_value=1,max_value=500"` // Max idle connections per coalescing group (optional, inherits from global, max: 500)
	IdleConnTimeout          reqctx.Duration `json:"idle_conn_timeout,omitempty" validate:"max_value=1h"`                    // Idle connection timeout (optional, inherits from global, max: 1h)
	MaxConnLifetime          reqctx.Duration `json:"max_conn_lifetime,omitempty" validate:"max_value=24h"`                   // Maximum connection lifetime (optional, inherits from global, max: 24h)
	AllowIPBasedCoalescing   bool            `json:"allow_ip_based_coalescing,omitempty"`                                    // Allow coalescing by IP address (optional, inherits from global)
	AllowCertBasedCoalescing bool            `json:"allow_cert_based_coalescing,omitempty"`                                  // Allow coalescing by certificate SAN (optional, inherits from global)
	StrictCertValidation     bool            `json:"strict_cert_validation,omitempty"`                                       // Strict certificate validation (optional, inherits from global)
}

// RequestCoalescingConfig represents request coalescing configuration
// Used for per-origin overrides (inherits from global config if not set)
type RequestCoalescingConfig struct {
	Enabled         bool            `json:"enabled,omitempty"`                                             // Enable request coalescing (optional, inherits from global, default: false)
	MaxInflight     int             `json:"max_inflight,omitempty" validate:"min_value=1,max_value=10000"` // Maximum in-flight coalesced requests (optional, inherits from global, max: 10000)
	CoalesceWindow  reqctx.Duration `json:"coalesce_window,omitempty" validate:"max_value=1s"`             // Time window for coalescing (optional, inherits from global, max: 1s)
	MaxWaiters      int             `json:"max_waiters,omitempty" validate:"min_value=1,max_value=1000"`   // Maximum waiters per request (optional, inherits from global, max: 1000)
	CleanupInterval reqctx.Duration `json:"cleanup_interval,omitempty" validate:"max_value=5m"`            // Cleanup interval for stale entries (optional, inherits from global, max: 5m)
	KeyStrategy     string          `json:"key_strategy,omitempty"`                                        // Key generation strategy: "default", "method_url", or custom (optional, inherits from global)
}

// TransportWrapperConfig represents transport wrapper configuration
type TransportWrapperConfig struct {
	// Retry configuration
	Retry *RetryConfig `json:"retry,omitempty"`

	// Hedging configuration
	Hedging *HedgingConfig `json:"hedging,omitempty"`

	// Health check configuration
	HealthCheck *TransportHealthCheckConfig `json:"health_check,omitempty"`
}

// RetryConfig configures automatic retry behavior
type RetryConfig struct {
	Enabled         bool            `json:"enabled"`
	MaxRetries      int             `json:"max_retries,omitempty" validate:"max_value=10,default_value=3"`                  // Maximum retry attempts (default: 3, max: 10)
	InitialDelay    reqctx.Duration `json:"initial_delay,omitempty" validate:"max_value=1m,default_value=100ms"`            // Initial delay before first retry (default: 100ms)
	MaxDelay        reqctx.Duration `json:"max_delay,omitempty" validate:"max_value=1m,default_value=10s"`                  // Maximum delay between retries (default: 10s)
	Multiplier      float64         `json:"multiplier,omitempty" validate:"min_value=1.0,max_value=10.0,default_value=2.0"` // Exponential backoff multiplier (default: 2.0)
	Jitter          float64         `json:"jitter,omitempty" validate:"min_value=0.0,max_value=1.0,default_value=0.1"`      // Jitter amount (0.0-1.0, default: 0.1)
	RetryableStatus []int           `json:"retryable_status,omitempty"`                                                     // HTTP status codes that trigger retry (default: [502, 503, 504, 429])
}

// HedgingConfig configures request hedging behavior
type HedgingConfig struct {
	Enabled             bool            `json:"enabled"`
	Delay               reqctx.Duration `json:"delay,omitempty" validate:"max_value=1m,default_value=100ms"`                       // Delay before sending hedge request (default: 100ms)
	MaxHedges           int             `json:"max_hedges,omitempty" validate:"min_value=1,max_value=3,default_value=1"`           // Maximum hedge requests (default: 1, max: 3)
	PercentileThreshold float64         `json:"percentile_threshold,omitempty"`                                                    // Percentile threshold for hedging (0.0-1.0)
	Methods             []string        `json:"methods,omitempty"`                                                                 // HTTP methods eligible for hedging (empty = all methods)
	MaxCostRatio        float64         `json:"max_cost_ratio,omitempty" validate:"min_value=0.0,max_value=1.0,default_value=0.2"` // Max ratio of hedged/total requests (default: 0.2)
}

// TransportHealthCheckConfig configures health checking for a backend in transport wrappers
type TransportHealthCheckConfig struct {
	Enabled            bool            `json:"enabled"`
	Type               string          `json:"type,omitempty"`                                                                     // "http", "https", or "tcp" (default: "http")
	Endpoint           string          `json:"endpoint,omitempty"`                                                                 // Health check endpoint (default: "/health")
	Host               string          `json:"host,omitempty"`                                                                     // Host header for health check (optional)
	Interval           reqctx.Duration `json:"interval,omitempty" validate:"max_value=1m,default_value=30s"`                       // Interval between health checks (default: 30s)
	Timeout            reqctx.Duration `json:"timeout,omitempty" validate:"max_value=1m,default_value=5s"`                         // Timeout for each health check (default: 5s)
	HealthyThreshold   int             `json:"healthy_threshold,omitempty" validate:"min_value=1,default_value=2"`                 // Consecutive successes needed to mark healthy (default: 2)
	UnhealthyThreshold int             `json:"unhealthy_threshold,omitempty" validate:"min_value=1,default_value=3"`               // Consecutive failures needed to mark unhealthy (default: 3)
	ExpectedStatus     int             `json:"expected_status,omitempty" validate:"min_value=100,max_value=599,default_value=200"` // Expected HTTP status code (default: 200)
	ExpectedBody       string          `json:"expected_body,omitempty"`                                                            // Expected response body substring (optional)
}

// ProxyConfig represents proxy origin configuration
type ProxyConfig struct {
	BaseConnection

	URL           string `json:"url"`
	Method        string `json:"method,omitempty"`
	AltHostname   string `json:"alt_hostname,omitempty"` // Set a different Host header when proxying to backend
	Hostname      string `json:"hostname,omitempty"`
	StripBasePath bool   `sb_flag:"strip_base_path" json:"strip_base_path,omitempty"`
	PreserveQuery bool   `sb_flag:"preserve_query" json:"preserve_query,omitempty"`

	// Shadow mirrors traffic asynchronously to a secondary upstream
	Shadow json.RawMessage `json:"shadow,omitempty"` // Enterprise: traffic shadowing

	// Canary enables weighted traffic splitting between primary and canary upstream
	Canary json.RawMessage `json:"canary,omitempty"` // Enterprise: canary routing
}

// DiscoveryConfig configures dynamic upstream resolution for load balancers.
type DiscoveryConfig struct {
	// Type is the discovery mechanism: "dns_srv" (OSS) or "consul" (enterprise).
	Type string `json:"type"`
	// Service is the DNS SRV service name (e.g., "_http._tcp.api.example.com").
	Service string `json:"service,omitempty"`
	// RefreshInterval is how often to re-resolve (default 30s).
	RefreshInterval string `json:"refresh_interval,omitempty"`
	// Resolver is an optional custom DNS resolver address (e.g., "8.8.8.8:53").
	Resolver string `json:"resolver,omitempty"`
}

// LoadBalancerConfig represents load balancer configuration
type LoadBalancerConfig struct {
	BaseAction

	Targets []Target `json:"targets"`

	// Discovery enables dynamic upstream resolution. When set, Targets may be
	// empty and backends are discovered at runtime.
	Discovery *DiscoveryConfig `json:"discovery,omitempty"`

	// Algorithm selects the load balancing strategy: "weighted_random" (default),
	// "round_robin", "weighted_round_robin", "least_connections", "ip_hash",
	// "uri_hash", "header_hash", "cookie_hash", "random", or "first".
	// When set, this takes precedence over the legacy RoundRobin/LeastConnections booleans.
	Algorithm string `json:"algorithm,omitempty"`

	// HashKey is the header name or cookie name used by the header_hash and cookie_hash algorithms.
	HashKey string `json:"hash_key,omitempty"`

	RoundRobin       bool `json:"round_robin,omitempty"`
	LeastConnections bool `json:"least_connections,omitempty"`
	DisableSticky    bool `json:"disable_sticky,omitempty"`

	// Sticky session cookie configuration (optional overrides)
	StickyCookieName string `json:"sticky_cookie_name,omitempty"`

	// Path and query handling
	// StripBasePath: if true, ignore the target URL's base path and use the request path as-is; if false (default), append request path to URL base path
	StripBasePath bool `sb_flag:"strip_base_path" json:"strip_base_path,omitempty"`
	// PreserveQuery: if true, use only request query; if false (default), merge target URL query with request query
	PreserveQuery bool `sb_flag:"preserve_query" json:"preserve_query,omitempty"`
}

// Target represents a load balancer target
type Target struct {
	BaseConnection

	URL    string `json:"url"`
	Weight int    `json:"weight,omitempty"`

	// Target can have its own modifiers
	RequestModifiers  modifier.RequestModifiers  `json:"request_modifiers,omitempty"`
	ResponseModifiers modifier.ResponseModifiers `json:"response_modifiers,omitempty"`

	// Target can have its own matcher for routing decisions
	RequestMatchers rule.RequestRules `json:"request_matchers,omitempty"`

	// Health check configuration
	HealthCheck *HealthCheckConfig `json:"health_check,omitempty"`

	// Circuit breaker configuration
	CircuitBreaker *CircuitBreakerConfig `json:"circuit_breaker,omitempty"`
}

// HealthCheckConfig defines health check parameters for a target
type HealthCheckConfig struct {
	Enabled  bool            `json:"enabled"`
	Interval reqctx.Duration `json:"interval,omitempty" validate:"max_value=1m,default_value=10s"` // How often to check (default: 10s)
	Timeout  reqctx.Duration `json:"timeout,omitempty" validate:"max_value=1m,default_value=5s"`   // Health check timeout (default: 5s)
	Path     string          `json:"path,omitempty"`                                               // HTTP path to check (default: "/")
	Method   string          `json:"method,omitempty"`                                             // HTTP method (default: "GET")

	// Success criteria
	ExpectedStatus []int `json:"expected_status,omitempty"` // Expected HTTP status codes (default: 200-299)

	// Thresholds
	HealthyThreshold   int `json:"healthy_threshold,omitempty" validate:"max_value=100"`   // Consecutive successes to mark healthy (default: 2, max: 100)
	UnhealthyThreshold int `json:"unhealthy_threshold,omitempty" validate:"max_value=100"` // Consecutive failures to mark unhealthy (default: 2, max: 100)
}

// CircuitBreakerConfig defines circuit breaker parameters for a target
type CircuitBreakerConfig struct {
	Enabled bool `json:"enabled"` // Enable circuit breaker

	// Failure thresholds
	FailureThreshold       int `json:"failure_threshold,omitempty" validate:"max_value=1000"`         // Number of failures to open circuit (default: 5, max: 1,000)
	SuccessThreshold       int `json:"success_threshold,omitempty" validate:"max_value=100"`          // Number of successes to close circuit from half-open (default: 2, max: 100)
	RequestVolumeThreshold int `json:"request_volume_threshold,omitempty" validate:"max_value=10000"` // Minimum requests before evaluating (default: 10, max: 10,000)

	// Time windows
	Timeout     reqctx.Duration `json:"timeout,omitempty" validate:"max_value=1m,default_value=30s"` // How long circuit stays open (default: 30s)
	SleepWindow reqctx.Duration `json:"sleep_window,omitempty" validate:"max_value=1m"`              // Alias for timeout (for compatibility)

	// Error rate threshold (alternative to failure count)
	ErrorRateThreshold float64 `json:"error_rate_threshold,omitempty"` // Error rate % to open circuit (default: 50%)

	// Half-open settings
	HalfOpenRequests int `json:"half_open_requests,omitempty" validate:"max_value=100"` // Number of test requests in half-open state (default: 3, max: 100)
}

// ErrorPage represents a custom error page configuration
type ErrorPage struct {
	// Status codes this error page applies to
	// If empty or nil, applies to all error status codes (4xx, 5xx)
	// If specified, only applies to those specific status codes
	Status []int `json:"status,omitempty"`

	// Callback to fetch error page content dynamically
	Callback *callback.Callback `json:"callback,omitempty"`

	// Static error page configuration (similar to StaticConfig)
	// Used when callback is not provided
	StatusCode  int               `json:"status_code,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	BodyBase64  string            `json:"body_base64,omitempty"`
	Body        string            `json:"body,omitempty"`
	JSONBody    json.RawMessage   `json:"json_body,omitempty"`

	// Template indicates if the body/content should be rendered as a template
	// When true, the body will be rendered as a Mustache template with the error context
	// Template has access to: status_code, error, request (url, method, headers), context
	Template bool `json:"template,omitempty"`

	// DecodeBase64 indicates if the callback response body is base64-encoded
	// When true, the callback response body will be base64-decoded before serving
	// This is useful for binary content (images, PDFs, etc.) fetched via callbacks
	DecodeBase64 bool `json:"decode_base64,omitempty"`
}

// ErrorPages is a collection of error page configurations
type ErrorPages []ErrorPage

// WebSocketConfig represents WebSocket proxy configuration
type WebSocketConfig struct {
	BaseConnection

	URL               string           `json:"url"` // Backend WebSocket URL (ws:// or wss://)
	StripBasePath     bool             `sb_flag:"strip_base_path" json:"strip_base_path,omitempty"`
	PreserveQuery     bool             `sb_flag:"preserve_query" json:"preserve_query,omitempty"`
	Provider          string           `json:"provider,omitempty"`                                                       // Optional provider hint (e.g. "openai")
	PingInterval      reqctx.Duration  `json:"ping_interval,omitempty" validate:"max_value=1m"`                          // Send ping frames (default: 0 = disabled)
	PongTimeout       reqctx.Duration  `json:"pong_timeout,omitempty" validate:"max_value=1m,default_value=10s"`         // Wait for pong response (default: 10s)
	IdleTimeout       reqctx.Duration  `json:"idle_timeout,omitempty" validate:"max_value=1h"`                           // Close connections after read inactivity
	ReadBufferSize    int              `json:"read_buffer_size,omitempty" validate:"max_value=10MB,default_value=4096"`  // Buffer size for reads (default: 4096)
	WriteBufferSize   int              `json:"write_buffer_size,omitempty" validate:"max_value=10MB,default_value=4096"` // Buffer size for writes (default: 4096)
	MaxFrameSize      int              `json:"max_frame_size,omitempty" validate:"max_value=10MB"`                       // Maximum size of a single message payload
	EnableCompression bool             `json:"enable_compression,omitempty"`                                             // Enable per-message compression
	HandshakeTimeout  reqctx.Duration  `json:"handshake_timeout,omitempty" validate:"max_value=1m,default_value=10s"`    // WebSocket handshake timeout (default: 10s)
	Subprotocols      []string         `json:"subprotocols,omitempty"`                                                   // Supported subprotocols
	AllowedOrigins    []string         `json:"allowed_origins,omitempty"`                                                // CORS origins (empty = all)
	CheckOrigin       bool             `json:"check_origin,omitempty"`                                                   // Enable origin checking
	Budget            *ai.BudgetConfig `json:"budget,omitempty"`                                                         // Optional token budget enforcement for provider-aware sessions
	EnableRFC8441     bool             `json:"enable_rfc8441,omitempty"`                                                 // Enable websocket-over-HTTP/2 extended CONNECT handling
	EnableRFC9220     bool             `json:"enable_rfc9220,omitempty"`                                                 // Enable websocket-over-HTTP/3 extended CONNECT handling (RFC 9220)

	// Connection pool settings
	DisablePool              bool            `json:"disable_pool,omitempty"`                                                  // Disable connection pooling (default: false, so pooling is enabled when compatible)
	PoolMaxConnections       int             `json:"pool_max_connections,omitempty" validate:"max_value=1000"`                // Maximum connections in pool (default: 100, max: 1,000)
	PoolMaxIdleConnections   int             `json:"pool_max_idle_connections,omitempty" validate:"max_value=100"`            // Maximum idle connections (default: 10, max: 100)
	PoolMaxLifetime          reqctx.Duration `json:"pool_max_lifetime,omitempty" validate:"max_value=1m"`                     // Maximum connection lifetime (default: 1h)
	PoolMaxIdleTime          reqctx.Duration `json:"pool_max_idle_time,omitempty" validate:"max_value=1m"`                    // Maximum idle time before closing (default: 5m)
	DisablePoolAutoReconnect bool            `json:"disable_pool_auto_reconnect,omitempty"`                                   // Disable automatic reconnection (default: false, so auto reconnect is enabled)
	PoolReconnectDelay       reqctx.Duration `json:"pool_reconnect_delay,omitempty" validate:"max_value=1m,default_value=5s"` // Reconnect delay (default: 5s)
	PoolMaxReconnectAttempts int             `json:"pool_max_reconnect_attempts,omitempty" validate:"max_value=100"`          // Max reconnect attempts (default: 3, max: 100, 0 = unlimited)
}

// Transforms is a slice type for transforms.
type Transforms []json.RawMessage

// TransformWhen holds conditional evaluation criteria for a transform.
// If set, the transform is only applied when all specified conditions match (AND logic).
// An unset condition is ignored.
type TransformWhen struct {
	ContentType  string   `json:"content_type,omitempty"`  // Match response content-type (prefix match)
	ContentTypes []string `json:"content_types,omitempty"` // Match any of these content-types
	StatusCode   int      `json:"status_code,omitempty"`   // Match exact status code
	StatusCodes  []int    `json:"status_codes,omitempty"`  // Match any of these status codes
	MinSize      int64    `json:"min_size,omitempty"`      // Only apply if body >= this size
	MaxSize      int64    `json:"max_size,omitempty"`      // Only apply if body <= this size
	Header       string   `json:"header,omitempty"`        // Only apply if this response header is present
}

// BaseTransform represents a base transformer.
type BaseTransform struct {
	TransformType string `json:"type"`
	Chain         string `json:"chain,omitempty"` // Reference to a named transform chain defined in transform_chains

	ContentTypes []string `json:"content_types,omitempty"` // Specific content types to match
	FailOnError  bool     `json:"fail_on_error" sb_flag:"fail_on_error"`
	Disabled     bool     `json:"disabled" sb_flag:"disabled"`
	MaxBodySize  int64    `json:"max_body_size,omitempty"` // Max response body size to transform (bytes). 0 = use default (10MB). -1 = unlimited.

	RequestMatcher  *rule.RequestRule  `json:"request_matcher,omitempty"`
	ResponseMatcher *rule.ResponseRule `json:"response_matcher,omitempty"`

	When *TransformWhen `json:"when,omitempty"` // Conditional evaluation criteria

	disabledByContentType map[string]bool         `json:"-"`
	tr                    transformer.Transformer `json:"-"`
}

// Auth represents a auth.
type Auth json.RawMessage

// Policy represents a policy.
type Policy json.RawMessage

// BasePolicy represents a base policy.
type BasePolicy struct {
	PolicyType string       `json:"type"`
	Disabled   bool         `json:"disabled,omitempty"`
	Match      *PolicyMatch `json:"match,omitempty"`
}

// HSTSConfig is an alias for the hsts middleware config type.
type HSTSConfig = hsts.Config

// CSPViolationReport is an alias for the csp middleware violation report type.
type CSPViolationReport = csp.ViolationReport

// RateLimit represents a rate limit.
type RateLimit struct {
	Algorithm         string  `json:"algorithm,omitempty"`
	RequestsPerMinute int     `json:"requests_per_minute,omitempty"`
	RequestsPerHour   int     `json:"requests_per_hour,omitempty"`
	RequestsPerDay    int     `json:"requests_per_day,omitempty"`
	BurstSize         int     `json:"burst_size,omitempty"`
	RefillRate        float64 `json:"refill_rate,omitempty"`
	QueueSize         int     `json:"queue_size,omitempty"`
	DrainRate         float64 `json:"drain_rate,omitempty"`
}

// RequestLimitingPolicy represents a request limiting policy.
type RequestLimitingPolicy struct {
	BasePolicy

	SizeLimits       *SizeLimitsConfig       `json:"size_limits,omitempty"`
	ComplexityLimits *ComplexityLimitsConfig `json:"complexity_limits,omitempty"`
}

// SizeLimitsConfig holds configuration for size limits.
type SizeLimitsConfig struct {
	MaxURLLength         int    `json:"max_url_length,omitempty"`
	MaxQueryStringLength int    `json:"max_query_string_length,omitempty"`
	MaxHeadersCount      int    `json:"max_headers_count,omitempty"`
	MaxHeaderSize        string `json:"max_header_size,omitempty" validate:"max_value=10MB"`   // e.g., "10KB", "1MB"
	MaxRequestSize       string `json:"max_request_size,omitempty" validate:"max_value=100MB"` // e.g., "10MB", "100MB"
}

// ComplexityLimitsConfig holds configuration for complexity limits.
type ComplexityLimitsConfig struct {
	MaxNestedDepth      int `json:"max_nested_depth,omitempty"`      // JSON nesting depth
	MaxObjectProperties int `json:"max_object_properties,omitempty"` // JSON object properties or query params
	MaxArrayElements    int `json:"max_array_elements,omitempty"`    // JSON array elements or form values
	MaxStringLength     int `json:"max_string_length,omitempty"`     // String length in JSON/query/form
}

// SemanticCacheConfig configures semantic similarity-based response caching for the AI gateway.
type SemanticCacheConfig struct {
	Enabled             bool     `json:"enabled"`
	EmbeddingProvider   string   `json:"embedding_provider,omitempty"`
	EmbeddingModel      string   `json:"embedding_model,omitempty"`
	SimilarityThreshold float64  `json:"similarity_threshold,omitempty"`
	TTLSeconds          int      `json:"ttl_seconds,omitempty"`
	MaxEntries          int      `json:"max_entries,omitempty"`
	Store               string   `json:"store,omitempty"`
	ExcludeModels       []string `json:"exclude_models,omitempty"`
	CacheBy             []string `json:"cache_by,omitempty"`
	CrossProvider       bool     `json:"cross_provider,omitempty"`
	NormalizePrompts    bool     `json:"normalize_prompts,omitempty"`
	Namespace           string   `json:"namespace,omitempty"`
}

// RewriteFn is a function type for rewrite fn callbacks.
type RewriteFn func(*httputil.ProxyRequest)

// ServeHTTP calls f(w, r).
func (f RewriteFn) Rewrite(pr *httputil.ProxyRequest) {
	f(pr)
}

// ErrorHandlerFn is a function type for error handler fn callbacks.
type ErrorHandlerFn func(http.ResponseWriter, *http.Request, error)

// ServeHTTP calls f(w, r).
func (f ErrorHandlerFn) ErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	f(w, r, err)
}

// ModifyResponseFn is a function type for modify response fn callbacks.
type ModifyResponseFn func(*http.Response) error

// ServeHTTP calls f(w, r).
func (f ModifyResponseFn) ModifyResponse(resp *http.Response) error {
	return f(resp)
}

// TransportFn is a function type for transport fn callbacks.
type TransportFn func(req *http.Request) (*http.Response, error)

// RoundTrip performs the round trip operation on the TransportFn.
func (f TransportFn) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// CookieJarFn is a function type for cookie jar fn callbacks.
type CookieJarFn func(*http.Request) http.CookieJar

// ClientHintsConfig configures HTTP Client Hints per RFC 8942.
// When enabled, the proxy injects Accept-CH and Critical-CH headers on responses
// and forwards client hint request headers to upstream origins.
type ClientHintsConfig struct {
	// Enable client hints processing.
	// Default: false
	Enable bool `json:"enable,omitempty" yaml:"enable,omitempty"`

	// AcceptCH lists the client hint headers the server wishes to receive.
	// These are sent in the Accept-CH response header.
	// Example: ["Sec-CH-UA", "Sec-CH-UA-Mobile", "DPR", "Viewport-Width"]
	AcceptCH []string `json:"accept_ch,omitempty" yaml:"accept_ch,omitempty"`

	// CriticalCH lists the client hint headers that are critical for correct
	// content selection. If missing, the client should retry the request.
	// These are sent in the Critical-CH response header.
	CriticalCH []string `json:"critical_ch,omitempty" yaml:"critical_ch,omitempty"`

	// Lifetime specifies the duration (in seconds) for which the client should
	// remember the Accept-CH preference. Sent as Accept-CH-Lifetime header.
	// 0 means omit the header (use browser default behavior).
	Lifetime int `json:"lifetime,omitempty" yaml:"lifetime,omitempty"`
}

// PrioritySchedulerConfig configures RFC 9218 priority-based response scheduling.
// When enabled, the proxy parses the Priority header and adjusts flush behavior
// based on urgency and incremental flags.
type PrioritySchedulerConfig struct {
	// Enable priority-based response scheduling.
	// Default: false
	Enable bool `json:"enable,omitempty" yaml:"enable,omitempty"`
}

// BotDetectionConfig configures bot detection for an origin.
// When enabled, incoming requests are checked against allow/deny lists and
// optionally verified via reverse DNS for known good bots.
type BotDetectionConfig struct {
	Enabled       bool     `json:"enabled"`
	Mode          string   `json:"mode"`            // "block", "challenge", "log" (default: "log")
	AllowList     []string `json:"allow_list"`      // Known good bot patterns matched against User-Agent
	DenyList      []string `json:"deny_list"`       // Known bad bot patterns matched against User-Agent
	ChallengeType string   `json:"challenge_type"`  // "js" (default) or "captcha"
	VerifyGoodBot bool     `json:"verify_good_bot"` // Verify good bots via reverse DNS lookup
}

// ThreatProtectionConfig holds JSON and XML structural validation settings
// to prevent payload-based attacks (deep nesting, key bombs, entity expansion, etc.).
type ThreatProtectionConfig struct {
	Enabled bool                   `json:"enabled"`
	JSON    *JSONThreatLimitConfig `json:"json,omitempty"`
	XML     *XMLThreatLimitConfig  `json:"xml,omitempty"`
}

// JSONThreatLimitConfig defines structural limits for JSON request bodies.
type JSONThreatLimitConfig struct {
	MaxDepth        int `json:"max_depth"`         // default 20
	MaxKeys         int `json:"max_keys"`          // default 1000
	MaxStringLength int `json:"max_string_length"` // default 200000 (200KB)
	MaxArraySize    int `json:"max_array_size"`    // default 10000
	MaxTotalSize    int `json:"max_total_size"`    // default 10485760 (10MB)
}

// XMLThreatLimitConfig defines structural limits for XML request bodies.
type XMLThreatLimitConfig struct {
	MaxDepth             int `json:"max_depth"`              // default 20
	MaxAttributes        int `json:"max_attributes"`         // default 100
	MaxChildren          int `json:"max_children"`           // default 10000
	EntityExpansionLimit int `json:"entity_expansion_limit"` // default 0 (disabled)
}

// FailsafeOrigin configures an explicit degraded-mode origin to load when the
// intended config cannot be loaded safely.
type FailsafeOrigin struct {
	Hostname     string          `json:"hostname"`
	Origin       json.RawMessage `json:"origin,omitempty"`
	ReasonHeader bool            `json:"reason_header,omitempty"`
}

// HasEmbeddedOrigin reports whether the FailsafeOrigin has embedded origin.
func (f *FailsafeOrigin) HasEmbeddedOrigin() bool {
	return f != nil && len(f.Origin) > 0
}

// HTTPMessageSignatureConfig is an alias for httpsig.Config.
type HTTPMessageSignatureConfig = httpsig.Config

var (
	// ErrUnauthorizedAPIAccess is a sentinel error for unauthorized api access conditions.
	ErrUnauthorizedAPIAccess = errors.New("config: unauthorized API access")
	// ErrNoTargets is a sentinel error for no targets conditions.
	ErrNoTargets = errors.New("config: no load balancer targets configured")
	// ErrInvalidTargetURL is a sentinel error for invalid target url conditions.
	ErrInvalidTargetURL = errors.New("config: invalid target URL")
	// ErrAllTargetsUnhealthy is a sentinel error returned when all load balancer targets are unhealthy.
	ErrAllTargetsUnhealthy = errors.New("config: all load balancer targets are unhealthy")
)

// ── websocket_message.go ──────────────────────────────────────────────────────

const (
	// MessageProtocolWebSocket is a constant for message protocol web socket.
	MessageProtocolWebSocket = "websocket"
	// MessagePhaseUpgrade is a constant for message phase upgrade.
	MessagePhaseUpgrade = "upgrade"
	// MessagePhaseMessage is a constant for message phase message.
	MessagePhaseMessage = "message"
	// MessageDirectionClientToBackend is a constant for message direction client to backend.
	MessageDirectionClientToBackend = "client_to_backend"
	// MessageDirectionBackendToClient is a constant for message direction backend to client.
	MessageDirectionBackendToClient = "backend_to_client"
	// WebSocketProviderOpenAI is a constant for web socket provider open ai.
	WebSocketProviderOpenAI = "openai"
)

// PolicyMatch scopes policy execution across protocol and websocket message metadata.
type PolicyMatch struct {
	Protocols  []string `json:"protocols,omitempty"`
	Phases     []string `json:"phases,omitempty"`
	Directions []string `json:"directions,omitempty"`
	EventTypes []string `json:"event_types,omitempty"`
	Providers  []string `json:"providers,omitempty"`
}

// MessageContext carries per-frame metadata through the websocket message pipeline.
type MessageContext struct {
	Protocol     string
	Phase        string
	Direction    string
	MessageType  int
	EventType    string
	Path         string
	Headers      http.Header
	Payload      []byte
	ConnectionID string
	Provider     string
	Request      *http.Request
	Metadata     map[string]any
}

// MessageHandler is a function type for message handler callbacks.
type MessageHandler func(context.Context, *MessageContext) error

// MessagePolicyConfig extends PolicyConfig with post-upgrade websocket message handling.
type MessagePolicyConfig interface {
	ApplyMessage(MessageHandler) MessageHandler
}

// MatchesMessage performs the matches message operation on the PolicyMatch.
func (m *PolicyMatch) MatchesMessage(msg *MessageContext) bool {
	if m == nil || msg == nil {
		return false
	}
	if len(m.Protocols) > 0 && !containsFold(m.Protocols, msg.Protocol) {
		return false
	}
	if len(m.Phases) > 0 && !containsFold(m.Phases, msg.Phase) {
		return false
	}
	if len(m.Directions) > 0 && !containsFold(m.Directions, msg.Direction) {
		return false
	}
	if len(m.EventTypes) > 0 && !containsFold(m.EventTypes, msg.EventType) {
		return false
	}
	if len(m.Providers) > 0 && !containsFold(m.Providers, msg.Provider) {
		return false
	}
	return true
}

func containsFold(values []string, target string) bool {
	target = strings.TrimSpace(target)
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), target) {
			return true
		}
	}
	return false
}

// ── fallback.go ───────────────────────────────────────────────────────────────

// FallbackOrigin configures an alternative origin that activates when the
// primary origin encounters specified error conditions.
type FallbackOrigin struct {
	Hostname       string            `json:"hostname"`
	Origin         json.RawMessage   `json:"origin,omitempty"`
	OnError        bool              `json:"on_error,omitempty"`
	OnTimeout      bool              `json:"on_timeout,omitempty"`
	OnStatus       []int             `json:"on_status,omitempty"`
	Timeout        reqctx.Duration   `json:"timeout,omitempty"`
	Rules          rule.RequestRules `json:"rules,omitempty"`
	MaxDepth       int               `json:"max_depth,omitempty"`
	AddDebugHeader bool              `json:"add_debug_header,omitempty"`
}

// ShouldTriggerOnError returns true if the fallback should activate for
// the given transport-level error. It checks both on_error and on_timeout
// conditions based on the error string patterns.
func (f *FallbackOrigin) ShouldTriggerOnError(err error) bool {
	if f == nil || err == nil {
		return false
	}
	errStr := err.Error()

	if f.OnTimeout {
		if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline") {
			return true
		}
	}

	if f.OnError {
		// Match the same error classifications as ErrorHandler in config_proxy.go
		if strings.Contains(errStr, "connection") ||
			strings.Contains(errStr, "refused") ||
			strings.Contains(errStr, "certificate") ||
			strings.Contains(errStr, "TLS") ||
			strings.Contains(errStr, "unhealthy") ||
			strings.Contains(errStr, "reset") ||
			strings.Contains(errStr, "broken pipe") ||
			strings.Contains(errStr, "DNS") {
			return true
		}
	}

	return false
}

// ShouldTriggerOnStatus returns true if the fallback should activate for
// the given upstream response status code.
func (f *FallbackOrigin) ShouldTriggerOnStatus(statusCode int) bool {
	if f == nil {
		return false
	}
	for _, s := range f.OnStatus {
		if s == statusCode {
			return true
		}
	}
	return false
}

// MatchesRequest returns true if the request is eligible for fallback
// based on the configured rules. If no rules are set, all requests match.
func (f *FallbackOrigin) MatchesRequest(req *http.Request) bool {
	if f == nil {
		return false
	}
	if len(f.Rules) == 0 {
		return true
	}
	return f.Rules.Match(req)
}

// HasEmbeddedOrigin reports whether the FallbackOrigin has embedded origin.
func (f *FallbackOrigin) HasEmbeddedOrigin() bool {
	return f != nil && len(f.Origin) > 0
}

// ── chunk_cache.go ────────────────────────────────────────────────────────────

// ChunkCacheConfig defines the configuration for chunk caching middleware.
// Supports both URL-based and signature-based (fingerprint) caching.
// If ChunkCacheConfig is present (not nil), chunk caching is enabled.
type ChunkCacheConfig struct {
	// URL-based caching (cache by request URL)
	URLCache URLCacheConfig `json:"url_cache,omitempty"`

	// Signature-based caching (cache by response signature/fingerprint)
	SignatureCache SignatureCacheConfig `json:"signature_cache,omitempty"`

	// Ignore Cache-Control: no-cache header from client
	IgnoreNoCache bool `json:"ignore_no_cache,omitempty"`
}

// URLCacheConfig defines URL-based chunk caching.
type URLCacheConfig struct {
	Enabled bool            `json:"enabled"`
	TTL     reqctx.Duration `json:"ttl,omitempty"` // Default: 1h
}

// SignatureCacheConfig defines signature-based chunk caching (fingerprint).
// Caches response prefixes based on matching signatures in the response body.
type SignatureCacheConfig struct {
	Enabled bool `json:"enabled"`

	// Content types to examine for signature matching
	ContentTypes []string `json:"content_types,omitempty"` // Default: ["text/html"]

	// Signature patterns to match against response prefixes
	Signatures []SignaturePattern `json:"signatures,omitempty"`

	// Maximum bytes to examine for signature matching
	MaxExamineBytes int `json:"max_examine_bytes,omitempty"` // Default: 8192

	// Default TTL for cached prefixes (can be overridden per signature)
	DefaultTTL reqctx.Duration `json:"default_ttl,omitempty"` // Default: 30m
}

// SignaturePattern defines a pattern to match in response bodies.
type SignaturePattern struct {
	// Human-readable name for this signature
	Name string `json:"name"`

	// Pattern type: "exact", "regex", "hash"
	PatternType string `json:"pattern_type"`

	// For "exact" type: Base64-encoded bytes to match at start of response
	ExactBytes string `json:"exact_bytes,omitempty"`

	// For "regex" type: Regular expression to match
	RegexPattern string `json:"regex_pattern,omitempty"`

	// For "hash" type: Expected hash value
	HashPattern string `json:"hash_pattern,omitempty"`

	// For "hash" type: Number of bytes to hash
	HashLength int `json:"hash_length,omitempty"`

	// For "hash" type: Hash algorithm ("xxhash", "sha256")
	HashAlgorithm string `json:"hash_algorithm,omitempty"`

	// Maximum bytes to examine for this signature (overrides global)
	MaxExamineBytes int `json:"max_examine_bytes,omitempty"`

	// TTL for this signature's cached prefix (overrides default)
	CacheTTL reqctx.Duration `json:"cache_ttl,omitempty"`

	// Minimum length of prefix to cache
	MinPrefixLength int `json:"min_prefix_length,omitempty"`

	// Maximum length of prefix to cache
	MaxPrefixLength int `json:"max_prefix_length,omitempty"`
}

// ── proxy_defaults.go ─────────────────────────────────────────────────────────

var (
	// DefaultProxyProtocol provides secure-by-default proxy protocol behavior.
	DefaultProxyProtocol = &ProxyProtocolConfig{
		AllowTrace:              false,
		DisableRequestSmuggling: false,
		DisableMaxForwards:      false,
		DisableAutoDate:         false,
		InterimResponses: &InterimResponseConfig{
			Forward100Continue:   false,
			Forward103EarlyHints: false,
			ForwardOther:         false,
		},
	}

	// DefaultProxyHeaders provides standard proxy header behavior.
	DefaultProxyHeaders = &ProxyHeaderConfig{
		TrustMode:      TrustAll,
		TrustedProxies: nil,
		TrustedHops:    0,
		XForwardedFor: &XForwardedForConfig{
			Mode: XFFAppend,
		},
		XForwardedProto: &XForwardedProtoConfig{
			Mode: XFPSet,
		},
		XForwardedHost: &XForwardedHostConfig{
			Mode: XFHSet,
		},
		XForwardedPort: &XForwardedPortConfig{
			Mode: XFPSet,
		},
		DisableXRealIP: false,
		Forwarded:      nil, // Not sent by default
		Via: &ViaHeaderConfig{
			Disable: false,
		},
		DisableServerHeaderRemoval: false,
		StripInternalHeaders:       nil,
		StripClientHeaders:         nil,
		AdditionalHopByHopHeaders:  nil,
		MaxRequestHeaderSize:       "1MB",
		MaxResponseHeaderSize:      "1MB",
		MaxHeaderCount:             100,
		PreserveHostHeader:         false,
		OverrideHost:               "",
		DisableHeaderNormalization: false,
	}

	// DefaultStreamingConfig provides standard streaming behavior.
	DefaultStreamingConfig = &StreamingProxyConfig{
		DisableRequestChunking:        false,
		DisableResponseChunking:       false,
		ChunkThreshold:                "8KB",
		ChunkSize:                     "32KB",
		DisableTrailers:               false,
		DisableTrailerAnnouncement:    false,
		DisableTrailerForwarding:      false,
		GenerateTrailers:              nil,
		DisableSmallResponseBuffering: false,
		BufferSizeThreshold:           "64KB",
		ProxyBufferSize:               "32KB",
		DefaultFlushInterval:          "", // Empty = auto-detect
		ForceFlushHeaders:             false,
	}
)

// ── constants.go ──────────────────────────────────────────────────────────────

const (
	// DefaultCacheDuration is the default value for cache duration.
	DefaultCacheDuration = 1 * time.Hour

	// TypeLoadBalancer is a constant for type load balancer.
	TypeLoadBalancer = "loadbalancer"
	// TypeWebSocket is a constant for type web socket.
	TypeWebSocket = "websocket"

	// Load balancer algorithm constants.
	// AlgorithmWeightedRandom selects targets randomly, weighted by their weight field (default).
	AlgorithmWeightedRandom = "weighted_random"
	// AlgorithmRoundRobin selects targets in sequential order.
	AlgorithmRoundRobin = "round_robin"
	// AlgorithmWeightedRoundRobin selects targets in sequential order, proportional to weight.
	AlgorithmWeightedRoundRobin = "weighted_round_robin"
	// AlgorithmLeastConnections selects the target with the fewest active connections.
	AlgorithmLeastConnections = "least_connections"
	// AlgorithmIPHash hashes the client IP for consistent routing; same IP always goes to same backend.
	AlgorithmIPHash = "ip_hash"
	// AlgorithmURIHash hashes the request URL path for consistent routing; same path goes to same backend.
	AlgorithmURIHash = "uri_hash"
	// AlgorithmHeaderHash hashes a specified request header value (requires hash_key config field).
	AlgorithmHeaderHash = "header_hash"
	// AlgorithmCookieHash hashes a specified cookie value (requires hash_key config field).
	AlgorithmCookieHash = "cookie_hash"
	// AlgorithmRandom selects a target with equal probability (ignores weights).
	AlgorithmRandom = "random"
	// AlgorithmFirst selects the first healthy target in list order (primary/failover pattern).
	AlgorithmFirst = "first"

	// TransformEncoding is a constant for transform encoding.
	TransformEncoding = "encoding"
	// TransformReplaceStrings is a constant for transform replace strings.
	TransformReplaceStrings = "replace_strings"
	// TransformLuaJSON is a constant for transform lua json.
	TransformLuaJSON = "lua_json"
)

// ── http2_xnet_extended_connect.go ───────────────────────────────────────────

var http2ExtendedConnectRuntimeEnabled atomic.Bool

// HTTP2ExtendedConnectRuntimeEnabled reports whether any loaded config has requested
// RFC 8441 / extended CONNECT server support.
func HTTP2ExtendedConnectRuntimeEnabled() bool {
	return http2ExtendedConnectRuntimeEnabled.Load()
}
