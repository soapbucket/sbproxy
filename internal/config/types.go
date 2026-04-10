// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai"
	"github.com/soapbucket/sbproxy/internal/security/certpin"
	"github.com/soapbucket/sbproxy/internal/config/callback"
	"github.com/soapbucket/sbproxy/internal/config/modifier"
	"github.com/soapbucket/sbproxy/internal/config/rule"
	"github.com/soapbucket/sbproxy/internal/config/waf"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/security/signature"
	"github.com/soapbucket/sbproxy/internal/transformer"
)

// SessionConfig holds configuration for session.
type SessionConfig struct {
	Disabled bool `sb_flag:"disabled" json:"disabled,omitempty"`

	CookieName      string `json:"cookie_name,omitempty"`
	CookieMaxAge    int    `json:"cookie_max_age,omitempty"`
	CookieSameSite  string `json:"cookie_same_site,omitempty"`
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
	MaxCookies      int  `json:"max_cookies,omitempty"`       // Maximum number of cookies to store per session (default: 100, max: 500)
	MaxCookieSize   int  `json:"max_cookie_size,omitempty"`   // Maximum size of a single cookie value in bytes (default: 4096, max: 16384)
	StoreSecureOnly bool `json:"store_secure_only,omitempty"` // Only store cookies with Secure flag set (default: false)
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

// AuthListConfig holds configuration for auth list.
type AuthListConfig struct {
	Whitelist []string `json:"whitelist,omitempty"`
	Blacklist []string `json:"blacklist,omitempty"`
}

// JWTConfig holds configuration for jwt.
type JWTConfig struct {
	BaseAuthConfig

	// Signing key/secret for HMAC algorithms or base64 encoded public key for RSA/ECDSA
	Secret            string             `json:"secret,omitempty" secret:"true"`
	PublicKey         string             `json:"public_key,omitempty"`
	PublicKeyCallback *callback.Callback `json:"public_key_callback,omitempty"`

	// JWKS (JSON Web Key Set) support
	JWKSURL               string             `json:"jwks_url,omitempty"`                                     // URL to fetch JWKS from
	JWKSURLCallback       *callback.Callback `json:"jwks_url_callback,omitempty"`                            // Dynamic JWKS URL via callback
	JWKSCacheDuration     reqctx.Duration    `json:"jwks_cache_duration,omitempty" validate:"max_value=24h"` // How long to cache JWKS (default: 1h, max: 24h)
	DisableJWKSRefreshUnknownKID bool        `json:"disable_jwks_refresh_unknown_kid,omitempty"`             // If true, do not refresh JWKS when kid is not found (default: false, so refresh is enabled)

	// JWT validation parameters
	Issuer    string   `json:"issuer,omitempty"`    // Expected issuer (iss claim)
	Audience  string   `json:"audience,omitempty"`  // Expected audience (aud claim)
	Audiences []string `json:"audiences,omitempty"` // Multiple expected audiences
	Algorithm string   `json:"algorithm,omitempty"` // Signing algorithm (default: RS256)

	// Token extraction
	HeaderName   string `json:"header_name,omitempty"`   // Header to extract token from (default: Authorization)
	HeaderPrefix string `json:"header_prefix,omitempty"` // Prefix to strip (default: "Bearer ")
	CookieName   string `json:"cookie_name,omitempty"`   // Alternative: extract from cookie
	QueryParam   string `json:"query_param,omitempty"`   // Alternative: extract from query param

	// Claims
	ClaimsNamespace string `json:"claims_namespace,omitempty"` // Namespace for custom claims

	// Cache public keys (for performance)
	CacheDuration reqctx.Duration `json:"cache_duration,omitempty" validate:"max_value=24h"` // Cache duration (max: 24h)

	AuthListConfig   *AuthListConfig    `json:"auth_list,omitempty"`
	AuthListCallback *callback.Callback `json:"auth_list_callback,omitempty"`
}

// APIKeyConfig holds configuration for api key.
type APIKeyConfig struct {
	BaseAuthConfig

	APIKeys         []string           `json:"api_keys" secret:"true"`
	APIKeysCallback *callback.Callback `json:"api_keys_callback,omitempty"`
}

// BasicAuthUser represents a basic auth user.
type BasicAuthUser struct {
	Username string `json:"username"`
	Password string `json:"password" secret:"true"`
}

// BasicAuthConfig holds configuration for basic auth.
type BasicAuthConfig struct {
	BaseAuthConfig

	Users         []BasicAuthUser    `json:"users"`
	UsersCallback *callback.Callback `json:"users_callback,omitempty"`
}

// BearerTokenConfig holds configuration for bearer token.
type BearerTokenConfig struct {
	BaseAuthConfig

	Tokens         []string           `json:"tokens" secret:"true"`
	TokensCallback *callback.Callback `json:"tokens_callback,omitempty"`
}

// ForwardAuthConfig holds configuration for forward auth.
// Forward auth delegates authentication to an external service by sending a subrequest.
type ForwardAuthConfig struct {
	BaseAuthConfig

	URL            string          `json:"url"`
	Method         string          `json:"method,omitempty"`
	TrustHeaders   []string        `json:"trust_headers,omitempty"`
	ForwardHeaders []string        `json:"forward_headers,omitempty"`
	ForwardBody    bool            `json:"forward_body,omitempty"`
	CacheDuration  reqctx.Duration `json:"cache_duration,omitempty"`
	CacheKey       string          `json:"cache_key,omitempty"`
	SuccessStatus  []int           `json:"success_status,omitempty"`
	Timeout        reqctx.Duration `json:"timeout,omitempty"`
}

// OAuthConfig holds configuration for OAuth 2.0 and OIDC authentication.
type OAuthConfig struct {
	BaseAuthConfig

	Provider            string            `json:"provider,omitempty"`             // OAuth provider preset (google, github, etc.)
	Tenant              string            `json:"tenant,omitempty"`               // Tenant ID for multi-tenant providers (Auth0, Okta)
	TenantSubstitutions map[string]string `json:"tenant_substitutions,omitempty"` // Custom substitutions for provider URLs

	ClientID          string   `json:"client_id"`
	ClientSecret      string   `json:"client_secret" secret:"true"`
	RedirectURL       string   `json:"redirect_url"`
	SessionSecret     string   `json:"session_secret" secret:"true"`
	SessionCookieName string   `json:"session_cookie_name"`
	SessionMaxAge     int      `json:"session_max_age"`
	AuthURL           string   `json:"auth_url,omitempty"`
	TokenURL          string   `json:"token_url,omitempty"`
	Scopes            []string `json:"scopes,omitempty"`

	// OIDC fields. When Issuer is set and AuthURL/TokenURL are empty, the proxy
	// performs OIDC discovery at {Issuer}/.well-known/openid-configuration to
	// resolve endpoints automatically. DiscoveryURL overrides the default
	// discovery location. DiscoveryCacheTTL controls how long the discovery
	// document is cached (default 1h).
	Issuer            string          `json:"issuer,omitempty"`
	DiscoveryURL      string          `json:"discovery_url,omitempty"`
	DiscoveryCacheTTL reqctx.Duration `json:"discovery_cache_ttl,omitempty"`

	CallbackPath        string             `json:"callback_path,omitempty"`
	LoginPath           string             `json:"login_path,omitempty"`
	LogoutPath          string             `json:"logout_path,omitempty"`
	ForceAuthentication bool               `json:"force_authentication,omitempty"`
	DefaultRoles        Roles              `json:"default_roles,omitempty"`
	LogoutCallback      *callback.Callback `json:"logout_callback,omitempty"`

	// PKCE enables Proof Key for Code Exchange (OAuth 2.1 compliance).
	// When true, the authorization flow uses S256 code challenges to prevent
	// authorization code interception attacks. Defaults to true.
	PKCE *bool `json:"pkce,omitempty"`
}

// GRPCAuthConfig holds configuration for gRPC external auth (Envoy ext_authz compatible).
type GRPCAuthConfig struct {
	BaseAuthConfig

	Address      string          `json:"address"`                 // gRPC server address (host:port)
	Timeout      reqctx.Duration `json:"timeout,omitempty"`       // Default: 5s
	TLS          bool            `json:"tls,omitempty"`           // Use TLS for gRPC connection
	TLSCACert    string          `json:"tls_ca_cert,omitempty"`   // CA cert for TLS
	FailOpen     bool            `json:"fail_open,omitempty"`     // Allow on auth server error
	TrustHeaders []string        `json:"trust_headers,omitempty"` // Headers from auth response to add to request
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

	DisableFollowRedirects bool `sb_flag:"disable_follow_redirects" json:"disable_follow_redirects,omitempty"`
	DisableCompression     bool `sb_flag:"disable_compression" json:"disable_compression,omitempty"`
	SkipTLSVerifyHost      bool `sb_flag:"skip_tls_verify_host" json:"skip_tls_verify_host,omitempty"`
	MinTLSVersion          string `json:"min_tls_version,omitempty"`                               // Minimum TLS version for outbound connections ("1.2" or "1.3")
	HTTP11Only             bool `sb_flag:"http11_only" json:"http11_only,omitempty"`     // Force HTTP/1.1 (disables HTTP/2 and HTTP/3)
	MaxRedirects           int  `json:"max_redirects,omitempty" validate:"max_value=20"` // Maximum redirects to follow (max: 20)
	EnableHTTP3            bool `sb_flag:"enable_http3" json:"enable_http3,omitempty"`

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
	Shadow *ShadowConfig `json:"shadow,omitempty"`

	// Canary enables weighted traffic splitting between primary and canary upstream
	Canary *CanaryConfig `json:"canary,omitempty"`
}

// ShadowConfig configures traffic shadowing for the proxy action.
type ShadowConfig struct {
	UpstreamURL  string  `json:"upstream_url"`                // Required: target URL for shadowed traffic
	SampleRate   float64 `json:"sample_rate,omitempty"`       // 0.0 to 1.0 (default: 1.0)
	Percentage   int     `json:"percentage,omitempty"`        // 1-100 traffic sampling shorthand; takes precedence over SampleRate if set
	FailOnError  bool    `json:"fail_on_error,omitempty"`     // If true, shadow errors are surfaced instead of being silently ignored (default: false)
	HeadersOnly  bool    `json:"headers_only,omitempty"`      // If true, shadow only headers (no body) to save bandwidth

	// Request modifiers applied ONLY to the shadow request
	Modifiers []ShadowModifier `json:"modifiers,omitempty"`

	// Timeouts and circuit breaker
	Timeout         reqctx.Duration `json:"timeout,omitempty" validate:"max_value=30s,default_value=500ms"` // Shadow request timeout (default: 500ms)
	MaxConcurrent   int             `json:"max_concurrent,omitempty" validate:"max_value=1000"`              // Max concurrent shadow requests (default: 100)
	MaxBodySize     string          `json:"max_body_size,omitempty"`                                         // Disable shadowing above this size (default: "1MB")
	CircuitBreaker  *CircuitBreakerConfig `json:"circuit_breaker,omitempty"`                                 // Circuit breaker for shadow target
}

// ShadowModifier represents a modification applied to shadow requests.
type ShadowModifier struct {
	Headers *ShadowHeaderModifier `json:"headers,omitempty"`
}

// ShadowHeaderModifier modifies headers on shadow requests.
type ShadowHeaderModifier struct {
	Set    map[string]string `json:"set,omitempty"`
	Remove []string          `json:"remove,omitempty"`
}

// CanaryConfig configures canary/weighted routing at the proxy action level.
// Traffic is split between the primary upstream and a canary target based on percentage.
type CanaryConfig struct {
	Enabled      bool   `json:"enabled"`                    // Enable canary routing
	Percentage   int    `json:"percentage"`                 // 0-100, percentage of traffic to route to canary target
	Target       string `json:"target"`                     // Upstream URL for canary target
	StickyHeader string `json:"sticky_header,omitempty"`    // Optional header for deterministic routing (e.g., "X-Canary")
}

// HTTPCalloutConfig configures a mid-request HTTP callout for request enrichment.
// The callout is made to an external service; the response headers are injected into
// the upstream request before it is forwarded.
type HTTPCalloutConfig struct {
	URL        string            `json:"url"`                          // External service URL
	Timeout    reqctx.Duration   `json:"timeout,omitempty" validate:"max_value=30s,default_value=5s"` // Callout timeout (default: 5s)
	Method     string            `json:"method,omitempty"`             // HTTP method (default: GET)
	InjectInto string            `json:"inject_into,omitempty"`        // Where to inject response: "headers" (default)
	FailMode   string            `json:"fail_mode,omitempty"`          // "open" (continue without enrichment) or "closed" (return 502). Default: open
	Headers    map[string]string `json:"headers,omitempty"`            // Headers to send with the callout request
}

// MockConfig represents a mock/synthetic response action configuration.
type MockConfig struct {
	BaseAction

	StatusCode int               `json:"status_code,omitempty"` // HTTP status code (default: 200)
	Headers    map[string]string `json:"headers,omitempty"`     // Response headers
	Body       string            `json:"body,omitempty"`        // Response body (inline)
	Delay      reqctx.Duration   `json:"delay,omitempty" validate:"max_value=30s"` // Simulated delay before response
}

// RedirectConfig represents redirect origin configuration
type RedirectConfig struct {
	BaseAction

	URL           string `json:"url"`
	StatusCode    int    `json:"status_code,omitempty"`
	StripBasePath bool   `sb_flag:"strip_base_path" json:"strip_base_path,omitempty"`
	PreserveQuery bool   `sb_flag:"preserve_query" json:"preserve_query,omitempty"`
}

// StorageConfig represents cloud storage backend configuration
type StorageConfig struct {
	BaseAction

	Kind              string          `json:"kind"`
	ConnCacheDuration reqctx.Duration `json:"conn_cache_duration,omitempty" validate:"max_value=24h"` // Connection cache duration (max: 24h)

	Key           string `json:"key,omitempty" secret:"true"`
	Secret        string `json:"secret,omitempty" secret:"true"`
	Region        string `json:"region,omitempty"`
	ProjectID     string `json:"project_id,omitempty"`
	Bucket        string `json:"bucket"`
	Account       string `json:"account,omitempty"`
	Scopes        string `json:"scopes,omitempty"`
	TenantName    string `json:"tenant_name,omitempty"`
	TenantAuthURL string `json:"tenant_auth_url,omitempty"`
}

// LoadBalancerConfig represents load balancer configuration
type LoadBalancerConfig struct {
	BaseAction

	Targets []Target `json:"targets"`

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

// StaticConfig holds configuration for static.
type StaticConfig struct {
	BaseAction

	StatusCode  int               `json:"status_code,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	BodyBase64  string            `json:"body_base64,omitempty"`
	Body        string            `json:"body,omitempty"`
	JSONBody    json.RawMessage   `json:"json_body,omitempty"`
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

// BeaconConfig holds configuration for beacon.
type BeaconConfig struct {
	StaticConfig

	EmptyGIF bool `json:"empty_gif,omitempty"`
}

// EchoConfig holds configuration for echo.
type EchoConfig struct {
	BaseAction

	IncludeContext bool `json:"include_context,omitempty"`
}

// WebSocketConfig represents WebSocket proxy configuration
type WebSocketConfig struct {
	BaseConnection

	URL               string          `json:"url"` // Backend WebSocket URL (ws:// or wss://)
	StripBasePath     bool            `sb_flag:"strip_base_path" json:"strip_base_path,omitempty"`
	PreserveQuery     bool            `sb_flag:"preserve_query" json:"preserve_query,omitempty"`
	Provider          string          `json:"provider,omitempty"`                                                     // Optional provider hint (e.g. "openai")
	PingInterval      reqctx.Duration `json:"ping_interval,omitempty" validate:"max_value=1m"`                          // Send ping frames (default: 0 = disabled)
	PongTimeout       reqctx.Duration `json:"pong_timeout,omitempty" validate:"max_value=1m,default_value=10s"`         // Wait for pong response (default: 10s)
	IdleTimeout       reqctx.Duration `json:"idle_timeout,omitempty" validate:"max_value=1h"`                           // Close connections after read inactivity
	ReadBufferSize    int             `json:"read_buffer_size,omitempty" validate:"max_value=10MB,default_value=4096"`  // Buffer size for reads (default: 4096)
	WriteBufferSize   int             `json:"write_buffer_size,omitempty" validate:"max_value=10MB,default_value=4096"` // Buffer size for writes (default: 4096)
	MaxFrameSize      int             `json:"max_frame_size,omitempty" validate:"max_value=10MB"`                       // Maximum size of a single message payload
	EnableCompression bool            `json:"enable_compression,omitempty"`                                             // Enable per-message compression
	HandshakeTimeout  reqctx.Duration `json:"handshake_timeout,omitempty" validate:"max_value=1m,default_value=10s"`    // WebSocket handshake timeout (default: 10s)
	Subprotocols      []string        `json:"subprotocols,omitempty"`                                                   // Supported subprotocols
	AllowedOrigins    []string        `json:"allowed_origins,omitempty"`                                                // CORS origins (empty = all)
	CheckOrigin       bool            `json:"check_origin,omitempty"`                                                   // Enable origin checking
	Budget            *ai.BudgetConfig `json:"budget,omitempty"`                                                        // Optional token budget enforcement for provider-aware sessions
	EnableRFC8441     bool            `json:"enable_rfc8441,omitempty"`                                                 // Enable websocket-over-HTTP/2 extended CONNECT handling
	EnableRFC9220     bool            `json:"enable_rfc9220,omitempty"`                                                 // Enable websocket-over-HTTP/3 extended CONNECT handling (RFC 9220)

	// Connection pool settings
	DisablePool              bool            `json:"disable_pool,omitempty"`                                                  // Disable connection pooling (default: false, so pooling is enabled when compatible)
	PoolMaxConnections       int             `json:"pool_max_connections,omitempty" validate:"max_value=1000"`                // Maximum connections in pool (default: 100, max: 1,000)
	PoolMaxIdleConnections   int             `json:"pool_max_idle_connections,omitempty" validate:"max_value=100"`            // Maximum idle connections (default: 10, max: 100)
	PoolMaxLifetime          reqctx.Duration `json:"pool_max_lifetime,omitempty" validate:"max_value=1m"`                     // Maximum connection lifetime (default: 1h)
	PoolMaxIdleTime          reqctx.Duration `json:"pool_max_idle_time,omitempty" validate:"max_value=1m"`                    // Maximum idle time before closing (default: 5m)
	DisablePoolAutoReconnect bool            `json:"disable_pool_auto_reconnect,omitempty"`                                  // Disable automatic reconnection (default: false, so auto reconnect is enabled)
	PoolReconnectDelay       reqctx.Duration `json:"pool_reconnect_delay,omitempty" validate:"max_value=1m,default_value=5s"` // Reconnect delay (default: 5s)
	PoolMaxReconnectAttempts int             `json:"pool_max_reconnect_attempts,omitempty" validate:"max_value=100"`          // Max reconnect attempts (default: 3, max: 100, 0 = unlimited)
}

// GraphQLConfig holds configuration for graph ql.
type GraphQLConfig struct {
	BaseConnection

	URL                       string                     `json:"url"`                                                    // Backend GraphQL URL
	MaxDepth                  int                        `json:"max_depth,omitempty" validate:"max_value=50"`            // Maximum query depth (default: 10, max: 50)
	MaxComplexity             int                        `json:"max_complexity,omitempty" validate:"max_value=10000"`    // Maximum query complexity (default: 100, max: 10,000)
	MaxCost                   int                        `json:"max_cost,omitempty" validate:"max_value=100000"`         // Maximum query cost (default: 1000, max: 100,000)
	MaxAliases                int                        `json:"max_aliases,omitempty" validate:"max_value=100"`         // Maximum aliased fields per query (default: 10, max: 100)
	EnableIntrospection       bool                       `json:"enable_introspection,omitempty"`                         // Allow introspection queries (default: false)
	PersistentQueries         bool                       `json:"persistent_queries,omitempty"`                           // Enable persistent queries (default: false)
	PersistentQueriesMap      map[string]string          `json:"persistent_queries_map,omitempty"`                       // Map of query hash -> query string
	AutomaticPersistedQueries bool                       `json:"automatic_persisted_queries,omitempty"`                  // Enable APQ (Apollo spec)
	APQCacheSize              int                        `json:"apq_cache_size,omitempty" validate:"max_value=100000"`   // APQ cache size (default: 10000, max: 100,000)
	QueryCacheSize            int                        `json:"query_cache_size,omitempty" validate:"max_value=100000"` // Max queries to cache (default: 1000, max: 100,000)
	DisableQueryValidation    bool                       `json:"disable_query_validation,omitempty"`                     // Skip query validation (default: false)
	AllowedOperations         []string                   `json:"allowed_operations,omitempty"`                           // Allowed operation names (empty = all)
	FieldCosts                map[string]int             `json:"field_costs,omitempty"`                                  // Custom field costs (field -> cost)
	TypeCosts                 map[string]int             `json:"type_costs,omitempty"`                                   // Custom type costs (type -> cost)
	FieldRateLimits           map[string]*FieldRateLimit `json:"field_rate_limits,omitempty"`                            // Field-level rate limits

	// Query Optimization Features
	EnableQueryBatching      bool            `json:"enable_query_batching,omitempty"`                                      // Enable query batching (default: false)
	EnableQueryDeduplication bool            `json:"enable_query_deduplication,omitempty"`                                 // Enable query deduplication (default: false)
	EnableResultCaching      bool            `json:"enable_result_caching,omitempty"`                                      // Enable result caching (default: false)
	ResultCacheSize          int             `json:"result_cache_size,omitempty" validate:"max_value=100000"`              // Result cache size (default: 1000, max: 100,000)
	ResultCacheTTL           reqctx.Duration `json:"result_cache_ttl,omitempty" validate:"max_value=24h,default_value=5m"` // Result cache TTL (default: 5m, max: 24h)
	MaxBatchSize             int             `json:"max_batch_size,omitempty" validate:"max_value=1000"`                   // Maximum queries per batch (default: 10, max: 1,000)
	EnableOptimizationHints  bool            `json:"enable_optimization_hints,omitempty"`                                  // Include optimization hints in response (default: false)

	// Per-Operation Rate Limiting (applied after parsing the GraphQL operation type)
	QueryRateLimit        *OperationRateLimit `json:"query_rate_limit,omitempty"`        // Rate limit for query operations
	MutationRateLimit     *OperationRateLimit `json:"mutation_rate_limit,omitempty"`     // Rate limit for mutation operations
	SubscriptionRateLimit *OperationRateLimit `json:"subscription_rate_limit,omitempty"` // Rate limit for subscription operations
}

// FieldRateLimit defines rate limiting for specific GraphQL fields
type FieldRateLimit struct {
	RequestsPerMinute int `json:"requests_per_minute,omitempty"`
	RequestsPerHour   int `json:"requests_per_hour,omitempty"`
	CostPerRequest    int `json:"cost_per_request,omitempty"` // Cost units consumed per request
}

// OperationRateLimit defines per-operation-type rate limiting for GraphQL.
type OperationRateLimit struct {
	RequestsPerMinute int `json:"requests_per_minute,omitempty"` // Max requests per minute (0 = unlimited)
	RequestsPerHour   int `json:"requests_per_hour,omitempty"`   // Max requests per hour (0 = unlimited)
}

// GRPCConfig represents gRPC proxy configuration
type GRPCConfig struct {
	BaseConnection

	URL           string `json:"url"`                                                   // Backend gRPC URL (e.g., "grpc://example.com:50051" or "https://example.com:50051")
	StripBasePath bool   `sb_flag:"strip_base_path" json:"strip_base_path,omitempty"` // Strip base path, use request path as-is (default: true)
	PreserveQuery bool   `sb_flag:"preserve_query" json:"preserve_query,omitempty"`   // Preserve query parameters (default: true)

	// gRPC-Web support (for browser clients)
	EnableGRPCWeb bool `json:"enable_grpc_web,omitempty"` // Enable gRPC-Web protocol support (default: false)

	// Metadata manipulation
	ForwardMetadata bool `json:"forward_metadata,omitempty"` // Forward gRPC metadata headers (default: true)

	// Timeout settings
	MaxCallRecvMsgSize int `json:"max_call_recv_msg_size,omitempty" validate:"max_value=50MB"` // Maximum message size to receive (default: 4MB)
	MaxCallSendMsgSize int `json:"max_call_send_msg_size,omitempty" validate:"max_value=50MB"` // Maximum message size to send (default: 4MB)
}

// ABTestConfig represents A/B testing configuration
type ABTestConfig struct {
	BaseAction

	TestName     string          `json:"test_name,omitempty"`
	CookieName   string          `json:"cookie_name"`                                    // Default: "_ab_test"
	CookieTTL    reqctx.Duration `json:"cookie_ttl,omitempty" validate:"max_value=365d"` // Cookie TTL (default: 30d, max: 365d)
	CookieDomain string          `json:"cookie_domain,omitempty"`
	CookieSecret string          `json:"cookie_secret,omitempty" secret:"true"` // For HMAC signing
	Variants     []ABTestVariant `json:"variants"`

	Targeting      *ABTestTargeting `json:"targeting,omitempty"`
	GradualRollout *GradualRollout  `json:"gradual_rollout,omitempty"`
	Analytics      *ABTestAnalytics `json:"analytics,omitempty"`
}

// ABTestVariant represents a single A/B test variant
type ABTestVariant struct {
	Name   string          `json:"name"`
	Weight int             `json:"weight"` // 0-100
	Action json.RawMessage `json:"action"` // Any action type
}

// ABTestTargeting defines targeting rules for A/B test participation
type ABTestTargeting struct {
	IncludeRules *TargetingRules `json:"include_rules,omitempty"`
	ExcludeRules *TargetingRules `json:"exclude_rules,omitempty"`
}

// TargetingRules defines criteria for targeting specific users
type TargetingRules struct {
	UserAgents    []string          `json:"user_agents,omitempty"`
	IPAddresses   []string          `json:"ip_addresses,omitempty"` // CIDR notation
	Geolocations  []string          `json:"geolocations,omitempty"` // Country codes
	Headers       map[string]string `json:"headers,omitempty"`
	QueryParams   map[string]string `json:"query_params,omitempty"`
	CustomCELExpr string            `json:"custom_cel_expr,omitempty"`
}

// GradualRollout defines time-based percentage ramping
type GradualRollout struct {
	Enabled         bool            `json:"enabled"`
	StartPercentage int             `json:"start_percentage"`                   // 0-100
	EndPercentage   int             `json:"end_percentage"`                     // 0-100
	Duration        reqctx.Duration `json:"duration" validate:"max_value=365d"` // Campaign duration (max: 365d)
	StartTime       time.Time       `json:"start_time,omitempty"`
}

// ABTestAnalytics defines analytics tracking configuration
type ABTestAnalytics struct {
	WebhookURL      string            `json:"webhook_url,omitempty"`
	TrackAssignment bool              `json:"track_assignment,omitempty"`
	CustomHeaders   map[string]string `json:"custom_headers,omitempty"`
}

// Transforms is a slice type for transforms.
type Transforms []json.RawMessage

// BaseTransform represents a base transformer.
type BaseTransform struct {
	TransformType string `json:"type"`

	ContentTypes []string `json:"content_types,omitempty"` // Specific content types to match
	FailOnError  bool     `json:"fail_on_error" sb_flag:"fail_on_error"`
	Disabled     bool     `json:"disabled" sb_flag:"disabled"`
	MaxBodySize  int64    `json:"max_body_size,omitempty"` // Max response body size to transform (bytes). 0 = use default (10MB). -1 = unlimited.

	RequestMatcher  *rule.RequestRule  `json:"request_matcher,omitempty"`
	ResponseMatcher *rule.ResponseRule `json:"response_matcher,omitempty"`

	disabledByContentType map[string]bool     `json:"-"`
	tr                    transformer.Transformer `json:"-"`
}

// OptimizedFormatOptions holds configuration for optimized format.
type OptimizedFormatOptions struct {
	StripNewlines              bool `json:"strip_newlines,omitempty"`
	StripSpace                 bool `json:"strip_space,omitempty"`
	RemoveBooleanAttributes    bool `json:"remove_boolean_attributes,omitempty"`
	RemoveQuotesFromAttributes bool `json:"remove_quotes_from_attributes,omitempty"`
	RemoveTrailingSlashes      bool `json:"remove_trailing_slashes,omitempty"`
	StripComments              bool `json:"strip_comments,omitempty"`
	OptimizeAttributes         bool `json:"optimize_attributes,omitempty"`
	SortAttributes             bool `json:"sort_attributes,omitempty"`
}

// FormatOptions holds configuration for format.
type FormatOptions struct {
	OptimizedFormatOptions

	LowercaseTags       bool `json:"lowercase_tags,omitempty"`
	LowercaseAttributes bool `json:"lowercase_attributes,omitempty"`
}

// AttributeOptions holds configuration for attribute.
type AttributeOptions struct {
	AddUniqueIDs    bool   `json:"add_unique_ids,omitempty"`
	UniqueIDPrefix  string `json:"unique_id_prefix,omitempty"`
	ReplaceExisting bool   `json:"replace_existing,omitempty"`
	UseRandomSuffix bool   `json:"use_random_suffix,omitempty"`
}

// AddToTagConfig represents configuration for adding content to a specific tag
type AddToTagConfig struct {
	Tag             string `json:"tag"`                          // Tag name (e.g., "head", "body")
	AddBeforeEndTag *bool  `json:"add_before_end_tag,omitempty"` // nil/omitted = insert after opening tag, false = insert after opening tag, true = insert before closing tag
	Content         string `json:"content"`                      // HTML content to insert
}

// OptimizedHTMLTransform represents a optimized html transformer.
type OptimizedHTMLTransform struct {
	BaseTransform

	FormatOptions    *OptimizedFormatOptions `json:"format_options,omitempty"`
	AttributeOptions *AttributeOptions       `json:"attribute_options,omitempty"`
	AddToTags        []AddToTagConfig        `json:"add_to_tags,omitempty"`
}

// HTMLConfig represents HTML transformation configuration
type HTMLTransform struct {
	BaseTransform

	FormatOptions    *FormatOptions    `json:"format_options,omitempty"`
	AttributeOptions *AttributeOptions `json:"attribute_options,omitempty"`
	AddToTags        []AddToTagConfig  `json:"add_to_tags,omitempty"`
}

// ReplaceStrings represents string replacement configuration
type ReplaceStrings struct {
	Replacements []ReplaceString `json:"replacements,omitempty"`
}

// ReplaceString represents a single string replacement
type ReplaceString struct {
	Find    string `json:"find"`
	Replace string `json:"replace"`
	Regex   bool   `json:"regex,omitempty"`

	CELExpr   string `json:"cel_expr"`   // CEL expression for transformation
	LuaScript string `json:"lua_script"` // Lua script for transformation
}

// ReplaceStringTransform represents a replace string transformer.
type ReplaceStringTransform struct {
	BaseTransform

	ReplaceStrings ReplaceStrings `json:"replace_strings"`
}

// DiscardTransform represents a discard transformer.
type DiscardTransform struct {
	BaseTransform

	Bytes int `json:"bytes"`
}

// JSONRule represents a single JSON transformation rule
type JSONRule struct {
	Path  string `json:"path"`
	Value any    `json:"value"`
}

// JSONConfig represents JSON transformation configuration
type JSONTransform struct {
	BaseTransform

	RemoveEmptyObjects  bool `json:"remove_empty_objects"`
	RemoveEmptyArrays   bool `json:"remove_empty_arrays"`
	RemoveFalseBooleans bool `json:"remove_false_booleans"`
	RemoveEmptyStrings  bool `json:"remove_empty_strings"`
	RemoveZeroNumbers   bool `json:"remove_zero_numbers"`
	PrettyPrint         bool `json:"pretty_print"`

	Rules []JSONRule `json:"rules"`
}

// JavascriptTransform represents a javascript transformer.
type JavascriptTransform struct {
	BaseTransform

	NumberPrecision     int  `json:"number_precision,omitempty"`
	ChangeVariableNames bool `json:"change_variable_names,omitempty"`
	SupportedVersion    int  `json:"supported_version,omitempty"`
}

// CSSTransform represents a css transformer.
type CSSTransform struct {
	BaseTransform

	Precision int  `json:"precision,omitempty"`
	Inline    bool `json:"inline,omitempty"`
	Version   int  `json:"version,omitempty"`
}

// TemplateTransform represents a template transformer.
type TemplateTransform struct {
	BaseTransform

	Template string      `json:"template"`
	Data     interface{} `json:"data"`
}

// MarkdownTransform represents a markdown transformer.
type MarkdownTransform struct {
	BaseTransform

	Sanitize              bool `json:"sanitize,omitempty"`
	DisableTables          bool `json:"disable_tables,omitempty"`
	DisableFencedCode      bool `json:"disable_fenced_code,omitempty"`
	DisableAutolink        bool `json:"disable_autolink,omitempty"`
	DisableStrikethrough   bool `json:"disable_strikethrough,omitempty"`
	DisableTaskLists       bool `json:"disable_task_lists,omitempty"`
	DisableDefinitionLists bool `json:"disable_definition_lists,omitempty"`
	DisableFootnotes       bool `json:"disable_footnotes,omitempty"`
	DisableHeadingIDs      bool `json:"disable_heading_ids,omitempty"`
	DisableAutoHeadingIDs  bool `json:"disable_auto_heading_ids,omitempty"`

	// HTML rendering options
	SkipHTML           bool `json:"skip_html,omitempty"`
	UseXHTML           bool `json:"use_xhtml,omitempty"`
	Nofollow           bool `json:"nofollow,omitempty"`
	NoreferrerNoopener bool `json:"noreferrer_noopener,omitempty"`
	HrefTargetBlank    bool `json:"href_target_blank,omitempty"`

	// Cached parser/renderer config computed once via sync.Once.
	// Stored as int to avoid importing gomarkdown packages in types.go.
	extensions int       `json:"-"`
	htmlFlags  int       `json:"-"`
	initOnce   sync.Once `json:"-"`
}

// LuaJSONTransform transforms JSON response bodies using Lua scripts.
// The script must define a function: modify_json(data, ctx)
// that receives the parsed JSON as a Lua table and returns the transformed data.
type LuaJSONTransform struct {
	BaseTransform

	// LuaScript contains the Lua code that must define a modify_json(data, ctx) function.
	// The function receives the parsed JSON body as a Lua table and must return the
	// transformed data structure.
	//
	// Example:
	//   function modify_json(data, ctx)
	//     -- Convert keys to snake_case, transform values, etc.
	//     data.country = country_map[data.country] or data.country
	//     return data
	//   end
	LuaScript string `json:"lua_script"`

	// Timeout for Lua script execution (default: 100ms, max: 10s)
	Timeout reqctx.Duration `json:"timeout,omitempty" validate:"max_value=10s,default_value=100ms"`
}

// JSONSchemaTransform validates response JSON against a JSON Schema.
type JSONSchemaTransform struct {
	BaseTransform
	Schema json.RawMessage `json:"schema"`           // Inline JSON Schema
	Action string          `json:"action,omitempty"` // "validate" (reject 400), "warn" (log only), "strip" (remove invalid)
}

// JSONProjectionTransform extracts or removes fields from JSON responses.
type JSONProjectionTransform struct {
	BaseTransform
	Include []string `json:"include,omitempty"` // Fields to keep (gjson paths)
	Exclude []string `json:"exclude,omitempty"` // Fields to remove (gjson paths)
	Flatten bool     `json:"flatten,omitempty"` // Flatten nested structure
}

// PayloadLimitTransform enforces maximum response body size.
type PayloadLimitTransform struct {
	BaseTransform
	MaxSize int64  `json:"max_size"`          // Maximum body size in bytes
	Action  string `json:"action,omitempty"`  // "truncate", "reject" (413), "warn"
}

// FormatConvertTransform converts response body between formats.
type FormatConvertTransform struct {
	BaseTransform
	From string `json:"from"` // "xml", "csv", "yaml"
	To   string `json:"to"`   // "json"
}

// ClassifyTransform adds classification headers based on response content.
type ClassifyTransform struct {
	BaseTransform
	Rules      []ClassifyRule `json:"rules"`
	HeaderName string         `json:"header_name,omitempty"` // Default: "X-Content-Class"
}

// ClassifyRule defines a single classification rule.
type ClassifyRule struct {
	Name    string `json:"name"`              // Classification label
	Pattern string `json:"pattern,omitempty"` // Regex pattern to match
	CELExpr string `json:"cel_expr,omitempty"`
	JSONPath string `json:"json_path,omitempty"` // gjson path that must exist/match
}

// TokenCountTransform adds token count headers to LLM API responses.
type TokenCountTransform struct {
	BaseTransform
	Provider     string `json:"provider,omitempty"`      // "openai", "anthropic", "generic"
	Model        string `json:"model,omitempty"`         // Model name for accurate counting
	HeaderPrefix string `json:"header_prefix,omitempty"` // Default: "X-Token-Count"
}

// AISchemaTransform validates LLM API request/response schemas.
type AISchemaTransform struct {
	BaseTransform
	Provider string `json:"provider,omitempty"` // "openai", "anthropic", "generic"
	Action   string `json:"action,omitempty"`   // "validate", "warn", "fix"
	Strict   bool   `json:"strict,omitempty"`
}

// AICacheTransform caches LLM responses to reduce duplicate API calls.
type AICacheTransform struct {
	BaseTransform
	TTL            int      `json:"ttl,omitempty"`              // Cache TTL in seconds
	MaxCachedSize  int64    `json:"max_cached_size,omitempty"`  // Max response size to cache
	HashFields     []string `json:"hash_fields,omitempty"`      // Request fields to include in cache key
	ExcludeFields  []string `json:"exclude_fields,omitempty"`   // Request fields to exclude from cache key
	SkipStreaming  bool     `json:"skip_streaming,omitempty"`   // Don't cache streaming responses
}

// SSEChunkingTransform processes Server-Sent Events streams from LLM APIs.
type SSEChunkingTransform struct {
	BaseTransform
	Provider     string   `json:"provider,omitempty"`      // "openai", "anthropic"
	FilterEvents []string `json:"filter_events,omitempty"` // Event types to filter out
	BufferChunks int      `json:"buffer_chunks,omitempty"` // Number of chunks to buffer
}

// Auth represents a auth.
type Auth json.RawMessage

// Policy represents a policy.
type Policy json.RawMessage

// BasePolicy represents a base policy.
type BasePolicy struct {
	PolicyType string `json:"type"`
	Disabled   bool   `json:"disabled,omitempty"`
	Match      *PolicyMatch `json:"match,omitempty"`
}

// RequestSigningPolicy represents a request signing policy.
type RequestSigningPolicy struct {
	BasePolicy

	SignatureConfig *signature.SignatureConfig `json:"signature,omitempty"`
	VerifyConfig    *signature.SignatureConfig `json:"verify,omitempty"`

	// Enhanced verification options
	RequireTimestamp bool              `json:"require_timestamp,omitempty"`             // Require timestamp in signature
	MaxTimestampAge  int64             `json:"max_timestamp_age,omitempty"`             // Maximum age of timestamp in seconds (default: 300)
	RequireNonce     bool              `json:"require_nonce,omitempty"`                 // Require nonce in signature
	NonceTTL         int64             `json:"nonce_ttl,omitempty"`                     // TTL for nonce tracking in seconds (default: 3600)
	PerClientKeys    map[string]string `json:"per_client_keys,omitempty" secret:"true"` // Client ID -> secret/key mapping
	ClientIDHeader   string            `json:"client_id_header,omitempty"`              // Header name for client ID (default: "X-Client-ID")
}

// IPFilteringPolicy represents a ip filtering policy.
type IPFilteringPolicy struct {
	BasePolicy

	Whitelist         []string          `json:"whitelist,omitempty"`                                                // IPs or CIDR ranges
	Blacklist         []string          `json:"blacklist,omitempty"`                                                // IPs or CIDR ranges
	Action            string            `json:"action,omitempty"`                                                   // "allow", "block" (default: "block" for blacklist, "allow" for whitelist)
	TemporaryBans     map[string]string `json:"temporary_bans,omitempty"`                                           // IP -> duration (e.g., "1h", "30m")
	DynamicBlocklist  []string          `json:"dynamic_blocklist,omitempty"`                                        // URLs to fetch dynamic blocklists from
	BlocklistTTL      reqctx.Duration   `json:"blocklist_ttl,omitempty" validate:"max_value=30d,default_value=24h"` // TTL for dynamic blocklist entries (default: 24h, max: 30d)
	TrustedProxyCIDRs []string          `json:"trusted_proxy_cidrs,omitempty"`                                      // CIDRs allowed to set X-Real-IP/X-Forwarded-For
}

// SecurityHeadersPolicy represents a security headers policy.
type SecurityHeadersPolicy struct {
	BasePolicy

	StrictTransportSecurity   *HSTSConfig                `json:"strict_transport_security,omitempty"`
	ContentSecurityPolicy     *CSPConfig                 `json:"content_security_policy,omitempty"`
	XFrameOptions             *XFrameOptionsConfig       `json:"x_frame_options,omitempty"`
	XContentTypeOptions       *XContentTypeOptionsConfig `json:"x_content_type_options,omitempty"`
	XXSSProtection            *XXSSProtectionConfig      `json:"x_xss_protection,omitempty"`
	ReferrerPolicy            *ReferrerPolicyConfig      `json:"referrer_policy,omitempty"`
	PermissionsPolicy         *PermissionsPolicyConfig   `json:"permissions_policy,omitempty"`
	CrossOriginEmbedderPolicy *COEPConfig                `json:"cross_origin_embedder_policy,omitempty"`
	CrossOriginOpenerPolicy   *COOPConfig                `json:"cross_origin_opener_policy,omitempty"`
	CrossOriginResourcePolicy *CORPConfig                `json:"cross_origin_resource_policy,omitempty"`
}

// HSTSConfig holds configuration for hsts.
type HSTSConfig struct {
	Enabled           bool `json:"enabled,omitempty"`
	MaxAge            int  `json:"max_age,omitempty"` // in seconds
	IncludeSubdomains bool `json:"include_subdomains,omitempty"`
	Preload           bool `json:"preload,omitempty"`
}

// CSPConfig holds configuration for csp.
type CSPConfig struct {
	Enabled    bool   `json:"enabled,omitempty"`
	Policy     string `json:"policy,omitempty"` // Simple string policy (for backward compatibility)
	ReportOnly bool   `json:"report_only,omitempty"`
	ReportURI  string `json:"report_uri,omitempty"`

	// Enhanced CSP features
	Directives    *CSPDirectives        `json:"directives,omitempty"`     // Structured directives
	EnableNonce   bool                  `json:"enable_nonce,omitempty"`   // Enable nonce generation
	EnableHash    bool                  `json:"enable_hash,omitempty"`    // Enable hash calculation
	DynamicRoutes map[string]*CSPConfig `json:"dynamic_routes,omitempty"` // Route-specific CSP
}

// CSPDirectives represents structured CSP directives
type CSPDirectives struct {
	DefaultSrc              []string `json:"default_src,omitempty"`
	ScriptSrc               []string `json:"script_src,omitempty"`
	StyleSrc                []string `json:"style_src,omitempty"`
	ImgSrc                  []string `json:"img_src,omitempty"`
	FontSrc                 []string `json:"font_src,omitempty"`
	ConnectSrc              []string `json:"connect_src,omitempty"`
	FrameSrc                []string `json:"frame_src,omitempty"`
	ObjectSrc               []string `json:"object_src,omitempty"`
	MediaSrc                []string `json:"media_src,omitempty"`
	FrameAncestors          []string `json:"frame_ancestors,omitempty"`
	BaseURI                 []string `json:"base_uri,omitempty"`
	FormAction              []string `json:"form_action,omitempty"`
	UpgradeInsecureRequests bool     `json:"upgrade_insecure_requests,omitempty"`
}

// CSPViolationReport represents a CSP violation report from the browser
type CSPViolationReport struct {
	Body struct {
		DocumentURI        string `json:"document-uri"`
		Referrer           string `json:"referrer"`
		ViolatedDirective  string `json:"violated-directive"`
		EffectiveDirective string `json:"effective-directive"`
		OriginalPolicy     string `json:"original-policy"`
		Disposition        string `json:"disposition"`
		BlockedURI         string `json:"blocked-uri"`
		LineNumber         int    `json:"line-number"`
		ColumnNumber       int    `json:"column-number"`
		SourceFile         string `json:"source-file"`
		StatusCode         int    `json:"status-code"`
		ScriptSample       string `json:"script-sample"`
	} `json:"csp-report"`
}

// XFrameOptionsConfig holds configuration for x frame.
type XFrameOptionsConfig struct {
	Enabled bool   `json:"enabled,omitempty"`
	Value   string `json:"value,omitempty"` // "DENY", "SAMEORIGIN", "ALLOW-FROM <uri>"
}

// XContentTypeOptionsConfig holds configuration for x content type.
type XContentTypeOptionsConfig struct {
	Enabled bool `json:"enabled,omitempty"`
	NoSniff bool `json:"no_sniff,omitempty"`
}

// XXSSProtectionConfig holds configuration for xxss protection.
type XXSSProtectionConfig struct {
	Enabled bool   `json:"enabled,omitempty"`
	Mode    string `json:"mode,omitempty"` // "0", "1", "block", "report"
}

// ReferrerPolicyConfig holds configuration for referrer policy.
type ReferrerPolicyConfig struct {
	Enabled bool   `json:"enabled,omitempty"`
	Policy  string `json:"policy,omitempty"` // "no-referrer", "no-referrer-when-downgrade", etc.
}

// PermissionsPolicyConfig holds configuration for permissions policy.
type PermissionsPolicyConfig struct {
	Enabled  bool              `json:"enabled,omitempty"`
	Features map[string]string `json:"features,omitempty"` // feature -> value mapping
}

// COEPConfig holds configuration for coep.
type COEPConfig struct {
	Enabled bool   `json:"enabled,omitempty"`
	Value   string `json:"value,omitempty"` // "unsafe-none", "require-corp"
}

// COOPConfig holds configuration for coop.
type COOPConfig struct {
	Enabled bool   `json:"enabled,omitempty"`
	Value   string `json:"value,omitempty"` // "unsafe-none", "same-origin-allow-popups", "same-origin"
}

// CORPConfig holds configuration for corp.
type CORPConfig struct {
	Enabled bool   `json:"enabled,omitempty"`
	Value   string `json:"value,omitempty"` // "same-site", "same-origin", "cross-origin"
}

// RateLimitingPolicy represents a rate limiting policy.
type RateLimitingPolicy struct {
	BasePolicy

	// Algorithm selection
	Algorithm string `json:"algorithm,omitempty"` // sliding_window, token_bucket, leaky_bucket, fixed_window

	// Default limits
	RequestsPerMinute int `json:"requests_per_minute,omitempty"`
	RequestsPerHour   int `json:"requests_per_hour,omitempty"`
	RequestsPerDay    int `json:"requests_per_day,omitempty"`

	// Token bucket specific
	BurstSize  int     `json:"burst_size,omitempty"`  // Max burst capacity
	RefillRate float64 `json:"refill_rate,omitempty"` // Tokens per second

	// Leaky bucket specific
	QueueSize int     `json:"queue_size,omitempty"` // Max queue size
	DrainRate float64 `json:"drain_rate,omitempty"` // Requests per second

	// IP lists
	Whitelist []string `json:"whitelist,omitempty"`
	Blacklist []string `json:"blacklist,omitempty"`

	// Custom limits
	CustomLimits   map[string]RateLimit `json:"custom_limits,omitempty"`   // IP -> custom limits
	EndpointLimits map[string]RateLimit `json:"endpoint_limits,omitempty"` // Endpoint pattern -> custom limits

	// Rate limit headers
	Headers RateLimitHeadersConfig `json:"headers,omitempty"`

	// Throttle configuration - queue requests instead of immediately rejecting with 429
	Throttle *ThrottleConfig `json:"throttle,omitempty"`

	// Quota configuration - per-consumer daily/monthly quota tracking
	Quota *QuotaConfig `json:"quota,omitempty"`

	// Smoothing configuration - gradual rate limit ramp-up for new consumers
	Smoothing *SmoothingConfig `json:"smoothing,omitempty"`
}

// ThrottleConfig configures request queuing/throttling behavior.
// When enabled, requests that exceed rate limits are queued instead of immediately rejected.
type ThrottleConfig struct {
	Enabled  bool            `json:"enabled,omitempty"`
	MaxQueue int             `json:"max_queue,omitempty"` // Max queued requests, default 100
	MaxWait  reqctx.Duration `json:"max_wait,omitempty"` // Max wait time, default 5s
}

// QuotaConfig configures per-consumer quota tracking with daily and monthly limits.
type QuotaConfig struct {
	Daily   int    `json:"daily,omitempty"`   // Max requests per day
	Monthly int    `json:"monthly,omitempty"` // Max requests per month
	Renewal string `json:"renewal,omitempty"` // "calendar" or "rolling", default "calendar"
}

// SmoothingConfig configures gradual rate limit ramp-up for new consumers.
// During the ramp period, the effective rate limit linearly increases from
// InitialRate * limit to 1.0 * limit.
type SmoothingConfig struct {
	RampDuration reqctx.Duration `json:"ramp_duration,omitempty"` // Time to reach full rate, default 1h
	InitialRate  float64         `json:"initial_rate,omitempty"`  // Starting rate multiplier (0.0-1.0), default 0.1
}

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

// RateLimitHeadersConfig holds configuration for rate limit headers.
type RateLimitHeadersConfig struct {
	// Enabled controls whether rate limit headers are added to responses
	Enabled bool `json:"enabled,omitempty"`

	// IncludeRetryAfter adds Retry-After header when rate limit is exceeded
	IncludeRetryAfter bool `json:"include_retry_after,omitempty"`

	// Header customization following IETF draft-polli-ratelimit-headers-02
	// https://www.ietf.org/archive/id/draft-polli-ratelimit-headers-02.html

	// IncludeLimit adds X-RateLimit-Limit header (requests quota in time window)
	IncludeLimit bool `json:"include_limit,omitempty"`

	// IncludeRemaining adds X-RateLimit-Remaining header (remaining requests in current window)
	IncludeRemaining bool `json:"include_remaining,omitempty"`

	// IncludeReset adds X-RateLimit-Reset header (seconds until window resets)
	IncludeReset bool `json:"include_reset,omitempty"`

	// IncludeUsed adds X-RateLimit-Used header (requests used in current window)
	IncludeUsed bool `json:"include_used,omitempty"`

	// ResetFormat controls the format of X-RateLimit-Reset header
	// "delta_seconds" (default, IETF spec) - seconds remaining until reset
	// "unix_timestamp" - Unix timestamp when the window resets
	ResetFormat string `json:"reset_format,omitempty"`

	// HeaderPrefix allows customizing the header prefix (default: "X-RateLimit")
	// Example: "X-RateLimit" produces "X-RateLimit-Limit", "X-RateLimit-Remaining", etc.
	HeaderPrefix string `json:"header_prefix,omitempty"`
}

// RequestLimitingPolicy represents a request limiting policy.
type RequestLimitingPolicy struct {
	BasePolicy

	SizeLimits       *SizeLimitsConfig       `json:"size_limits,omitempty"`
	ComplexityLimits *ComplexityLimitsConfig `json:"complexity_limits,omitempty"`
	Protection       *ProtectionConfig       `json:"protection,omitempty"`
}

// SizeLimitsConfig holds configuration for size limits.
type SizeLimitsConfig struct {
	MaxURLLength         int    `json:"max_url_length,omitempty"`
	MaxQueryStringLength int    `json:"max_query_string_length,omitempty"`
	MaxHeadersCount      int    `json:"max_headers_count,omitempty"`
	MaxHeaderSize        string `json:"max_header_size,omitempty" validate:"max_value=10MB"`   // e.g., "10KB", "1MB"
	MaxRequestSize       string `json:"max_request_size,omitempty" validate:"max_value=100MB"` // e.g., "10MB", "100MB"
}

// StreamingConfig configures streaming fallback for large request/response bodies
type StreamingConfig struct {
	// Enabled controls whether streaming fallback is active
	Enabled bool `json:"enabled,omitempty"`

	// MaxBufferedBodySize is the maximum body size before streaming fallback (default: 10MB)
	MaxBufferedBodySize string `json:"max_buffered_body_size,omitempty" validate:"max_value=10MB,default_value=10MB"` // e.g., "10MB"

	// MaxProcessableBodySize is the maximum body size to process at all (default: 100MB)
	MaxProcessableBodySize string `json:"max_processable_body_size,omitempty" validate:"max_value=100MB,default_value=100MB"` // e.g., "100MB"

	// Per-operation thresholds (override global MaxBufferedBodySize)
	ModifierThreshold  string `json:"modifier_threshold,omitempty" validate:"max_value=10MB"`  // Body modification threshold
	TransformThreshold string `json:"transform_threshold,omitempty" validate:"max_value=10MB"` // Transformation threshold
	SignatureThreshold string `json:"signature_threshold,omitempty" validate:"max_value=10MB"` // Signature verification threshold
	CallbackThreshold  string `json:"callback_threshold,omitempty" validate:"max_value=10MB"`  // Callback response threshold
}

// ComplexityLimitsConfig holds configuration for complexity limits.
type ComplexityLimitsConfig struct {
	MaxNestedDepth      int `json:"max_nested_depth,omitempty"`      // JSON nesting depth
	MaxObjectProperties int `json:"max_object_properties,omitempty"` // JSON object properties or query params
	MaxArrayElements    int `json:"max_array_elements,omitempty"`    // JSON array elements or form values
	MaxStringLength     int `json:"max_string_length,omitempty"`     // String length in JSON/query/form
}

// ProtectionConfig holds configuration for protection.
type ProtectionConfig struct {
	SlowlorisProtection bool            `json:"slowloris_protection,omitempty"`
	SlowReadProtection  bool            `json:"slow_read_protection,omitempty"`
	Timeout             reqctx.Duration `json:"timeout,omitempty" validate:"max_value=1m"`
}

// ThreatDetectionPolicy represents a threat detection policy.
type ThreatDetectionPolicy struct {
	BasePolicy

	Patterns           map[string]ThreatPatternConfig `json:"patterns,omitempty"`
	BehavioralAnalysis *BehavioralAnalysisConfig      `json:"behavioral_analysis,omitempty"`
}

// ThreatPatternConfig holds configuration for threat pattern.
type ThreatPatternConfig struct {
	Enabled  bool   `json:"enabled,omitempty"`
	Disabled bool   `json:"disabled,omitempty"`  // If true, Enabled is set to false
	Action   string `json:"action,omitempty"`    // "block", "log", "challenge"
	LogLevel string `json:"log_level,omitempty"` // "info", "warn", "error"
}

// BehavioralAnalysisConfig holds configuration for behavioral analysis.
type BehavioralAnalysisConfig struct {
	Enabled bool   `json:"enabled,omitempty"`
	Action  string `json:"action,omitempty"` // "block", "log", "challenge"
}

// DDoSProtectionPolicy represents a d do s protection policy.
type DDoSProtectionPolicy struct {
	BasePolicy

	Detection  *DDoSDetectionConfig  `json:"detection,omitempty"`
	Mitigation *DDoSMitigationConfig `json:"mitigation,omitempty"`
}

// ExpressionPolicy represents a expression policy.
type ExpressionPolicy struct {
	BasePolicy

	CELExpr    string `json:"cel_expr,omitempty"`    // CEL expression that returns boolean
	LuaScript  string `json:"lua_script,omitempty"`  // Lua script that returns boolean
	StatusCode int    `json:"status_code,omitempty"` // HTTP status code to return when blocking (default: 401 for auth, 403 for other)
}

// DDoSDetectionConfig holds configuration for d do s detection.
type DDoSDetectionConfig struct {
	RequestRateThreshold    int     `json:"request_rate_threshold,omitempty"`    // requests per window
	ConnectionRateThreshold int     `json:"connection_rate_threshold,omitempty"` // connections per window
	BandwidthThreshold      string  `json:"bandwidth_threshold,omitempty"`       // e.g., "100MB"
	DetectionWindow         string  `json:"detection_window,omitempty"`          // e.g., "10s", "1m"
	AdaptiveThresholds      bool    `json:"adaptive_thresholds,omitempty"`       // Enable adaptive thresholds based on normal traffic
	BaselineWindow          string  `json:"baseline_window,omitempty"`           // Window for baseline calculation (e.g., "1h", "24h")
	ThresholdMultiplier     float64 `json:"threshold_multiplier,omitempty"`      // Multiplier for adaptive thresholds (default: 2.0)
}

// DDoSMitigationConfig holds configuration for d do s mitigation.
type DDoSMitigationConfig struct {
	BlockDuration       string                     `json:"block_duration,omitempty"`     // e.g., "1h", "30m"
	ChallengeResponse   bool                       `json:"challenge_response,omitempty"` // Basic challenge-response
	ChallengeType       string                     `json:"challenge_type,omitempty"`     // "header", "proof_of_work", "javascript", "captcha"
	ProofOfWork         *ProofOfWorkConfig         `json:"proof_of_work,omitempty"`
	JavaScriptChallenge *JavaScriptChallengeConfig `json:"javascript_challenge,omitempty"`
	CAPTCHA             *CAPTCHAConfig             `json:"captcha,omitempty"`
	AutoBlock           bool                       `json:"auto_block,omitempty"`           // Automatically block attacker IPs
	BlockAfterAttacks   int                        `json:"block_after_attacks,omitempty"`  // Number of attacks before auto-block (default: 3)
	CustomHTMLCallback  json.RawMessage            `json:"custom_html_callback,omitempty"` // Callback to fetch custom HTML for challenge pages (deferred unmarshal)
}

// ProofOfWorkConfig holds configuration for proof of work.
type ProofOfWorkConfig struct {
	Enabled    bool   `json:"enabled,omitempty"`
	Difficulty int    `json:"difficulty,omitempty"`                      // Number of leading zeros required (default: 4)
	Timeout    string `json:"timeout,omitempty" validate:"max_value=1m"` // Timeout for proof-of-work (default: "30s")
	HeaderName string `json:"header_name,omitempty"`                     // Header name for proof-of-work (default: "X-Proof-Of-Work")
}

// JavaScriptChallengeConfig holds configuration for java script challenge.
type JavaScriptChallengeConfig struct {
	Enabled    bool   `json:"enabled,omitempty"`
	ScriptPath string `json:"script_path,omitempty"`                     // Path to JavaScript challenge script
	Timeout    string `json:"timeout,omitempty" validate:"max_value=1m"` // Timeout for JavaScript challenge (default: "60s")
	HeaderName string `json:"header_name,omitempty"`                     // Header name for challenge response (default: "X-JS-Challenge")
}

// CAPTCHAConfig holds configuration for captcha.
type CAPTCHAConfig struct {
	Enabled   bool   `json:"enabled,omitempty"`
	Provider  string `json:"provider,omitempty"`                 // "hcaptcha", "recaptcha", "turnstile"
	SiteKey   string `json:"site_key,omitempty"`                 // CAPTCHA site key
	SecretKey string `json:"secret_key,omitempty" secret:"true"` // CAPTCHA secret key
	VerifyURL string `json:"verify_url,omitempty"`               // CAPTCHA verification URL (optional, uses default if not set)
}

// CSRFPolicy represents a csrf policy.
type CSRFPolicy struct {
	BasePolicy

	CookieName     string   `json:"cookie_name,omitempty"`          // CSRF cookie name (default: "_csrf")
	CookiePath     string   `json:"cookie_path,omitempty"`          // Cookie path (default: "/")
	CookieDomain   string   `json:"cookie_domain,omitempty"`        // Cookie domain
	CookieSecure   bool     `json:"cookie_secure,omitempty"`        // Secure flag (default: true for HTTPS)
	CookieHttpOnly bool     `json:"cookie_http_only,omitempty"`     // HttpOnly flag (default: true)
	CookieSameSite string   `json:"cookie_same_site,omitempty"`     // SameSite: "Strict", "Lax", "None" (default: "Lax")
	HeaderName     string   `json:"header_name,omitempty"`          // Header name for AJAX (default: "X-CSRF-Token")
	FormFieldName  string   `json:"form_field_name,omitempty"`      // Form field name (default: "_csrf")
	Secret         string   `json:"secret,omitempty" secret:"true"` // Secret key for token signing (required)
	TokenLength    int      `json:"token_length,omitempty"`         // Token length in bytes (default: 32)
	Methods        []string `json:"methods,omitempty"`              // Methods to protect (default: ["POST", "PUT", "DELETE", "PATCH"])
	ExemptPaths    []string `json:"exempt_paths,omitempty"`         // Paths exempt from CSRF protection
}

// GeoBlockingPolicy represents a geo blocking policy.
type GeoBlockingPolicy struct {
	BasePolicy

	AllowedCountries []string `json:"allowed_countries,omitempty"` // ISO 3166-1 alpha-2 country codes (e.g., ["US", "CA"])
	BlockedCountries []string `json:"blocked_countries,omitempty"` // ISO 3166-1 alpha-2 country codes (e.g., ["CN", "RU"])
	Action           string   `json:"action,omitempty"`            // "block", "log", "redirect" (default: "block")
	RedirectURL      string   `json:"redirect_url,omitempty"`      // Redirect URL if action is "redirect"
	DBPath           string   `json:"db_path,omitempty"`           // Path to GeoIP2 database file
}

// SRIPolicy represents a sri policy.
type SRIPolicy struct {
	BasePolicy

	// Validation settings
	ValidateResponses      bool `json:"validate_responses,omitempty"`        // Validate SRI hashes in responses
	ValidateRequests       bool `json:"validate_requests,omitempty"`         // Validate SRI hashes in requests
	FailOnMissingIntegrity bool `json:"fail_on_missing_integrity,omitempty"` // Fail if integrity attribute is missing
	FailOnInvalidIntegrity bool `json:"fail_on_invalid_integrity,omitempty"` // Fail if integrity hash is invalid

	// Known hashes for validation (resource URL -> list of valid hashes)
	KnownHashes map[string][]string `json:"known_hashes,omitempty"`

	// Generator settings (for generating hashes)
	GenerateForContentTypes []string `json:"generate_for_content_types,omitempty"` // Content types to generate SRI for
	Algorithm               string   `json:"algorithm,omitempty"`                  // Hash algorithm: sha256, sha384 (default), sha512
}

// WAFPolicy represents a waf policy.
type WAFPolicy struct {
	BasePolicy

	// ModSecurity-compatible rules
	ModSecurityRules []string `json:"modsecurity_rules,omitempty"` // Raw ModSecurity rule strings

	// Custom rules
	CustomRules []waf.WAFRule `json:"custom_rules,omitempty"` // Custom rule definitions

	// OWASP Core Rule Set (CRS) configuration
	OWASPCRS *waf.OWASPCRSConfig `json:"owasp_crs,omitempty"` // OWASP CRS configuration

	// Rule sets
	RuleSets []string `json:"rule_sets,omitempty"` // Rule set names to load (e.g., "owasp-top10", "sql-injection")

	// Actions
	DefaultAction string `json:"default_action,omitempty"`  // "block", "log", "pass" (default: "log")
	ActionOnMatch string `json:"action_on_match,omitempty"` // Action when rule matches (default: "block")

	// Performance settings
	MaxRuleExecutionTime        reqctx.Duration `json:"max_rule_execution_time,omitempty" validate:"max_value=1m"` // Max time to spend evaluating rules (max: 1m)
	EnablePerformanceMonitoring bool            `json:"enable_performance_monitoring,omitempty"`                   // Track rule performance

	// Testing and validation
	TestMode bool `json:"test_mode,omitempty"` // Test mode (log but don't block)

	// Fail-open behavior
	FailOpen bool `json:"fail_open,omitempty"` // If true, allow request on WAF evaluation errors; if false (default), block on errors
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

// PIIPolicy configures PII detection and redaction as a policy.
type PIIPolicy struct {
	BasePolicy

	Mode       string `json:"mode"`                  // "block", "redact", "warn"
	Direction  string `json:"direction,omitempty"`    // "request", "response", "both" (default: "both")
	StatusCode int    `json:"status_code,omitempty"`  // HTTP status code for block mode (default: 403)

	Detectors       PIIDetectorConfig   `json:"detectors,omitempty"`
	CustomDetectors []PIICustomDetector `json:"custom_detectors,omitempty"`
	Allowlist       []PIIAllowlistEntry `json:"allowlist,omitempty"`

	MaxBodySize    int64    `json:"max_body_size,omitempty"`    // Max body size to scan in bytes (default: 1MB)
	ContentTypes   []string `json:"content_types,omitempty"`    // Content types to scan (default: JSON + text)
	LogFindings    bool     `json:"log_findings,omitempty"`     // Log detected PII types for audit
	IncludeHeaders bool     `json:"include_headers,omitempty"`  // Also scan headers
}

// PIIDetectorConfig toggles individual built-in detectors.
type PIIDetectorConfig struct {
	SSN                *bool `json:"ssn,omitempty"`                  // Default: true
	CreditCard         *bool `json:"credit_card,omitempty"`          // Default: true
	Email              *bool `json:"email,omitempty"`                // Default: true
	Phone              *bool `json:"phone,omitempty"`                // Default: true
	IPAddress          *bool `json:"ip_address,omitempty"`           // Default: false
	APIKey             *bool `json:"api_key,omitempty"`              // Default: true
	JWT                *bool `json:"jwt,omitempty"`                  // Default: true
	AWSKey             *bool `json:"aws_key,omitempty"`              // Default: false
	PrivateKey         *bool `json:"private_key,omitempty"`          // Default: false
	DBConnectionString *bool `json:"db_connection_string,omitempty"` // Default: false
}

// PIICustomDetector defines a Lua-based custom PII detector.
type PIICustomDetector struct {
	Name      string          `json:"name"`
	LuaScript string          `json:"lua_script"`
	Timeout   reqctx.Duration `json:"timeout,omitempty"` // Default: 100ms
}

// PIIAllowlistEntry exempts specific fields from PII detection.
type PIIAllowlistEntry struct {
	FieldPath    string `json:"field_path"`              // JSON path (supports wildcards)
	DetectorType string `json:"detector_type,omitempty"` // Specific detector or "" for all
	PathPrefix   string `json:"path_prefix,omitempty"`   // URL path prefix
}

// FaultInjectionPolicy holds configuration for fault injection policy.
type FaultInjectionPolicy struct {
	BasePolicy
	Delay            *DelayFault `json:"delay,omitempty"`
	Abort            *AbortFault `json:"abort,omitempty"`
	ActivationHeader string      `json:"activation_header,omitempty"`
}

// DelayFault configures delay injection.
type DelayFault struct {
	Duration   reqctx.Duration `json:"duration"`
	Percentage float64         `json:"percentage"`
}

// AbortFault configures abort injection.
type AbortFault struct {
	StatusCode int     `json:"status_code"`
	Percentage float64 `json:"percentage"`
	Body       string  `json:"body,omitempty"`
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

// APIVersionConfig holds configuration for API versioning.
type APIVersionConfig struct {
	Versions       []APIVersion `json:"versions,omitempty"`
	DefaultVersion string       `json:"default_version,omitempty"` // Version to use when none specified
	Location       string       `json:"location,omitempty"`        // "header", "url", "query" - where to extract version
	Key            string       `json:"key,omitempty"`             // Header name or query param name (e.g., "X-API-Version", "version")
}

// APIVersion represents a single API version.
type APIVersion struct {
	Name         string `json:"name"`                      // "v1", "v2", "2024-01-15"
	URLPrefix    string `json:"url_prefix,omitempty"`      // "/v1", "/v2"
	StripVersion bool   `json:"strip_version,omitempty"`   // Remove version prefix from forwarded path
	Deprecated   bool   `json:"deprecated,omitempty"`
	SunsetDate   string `json:"sunset_date,omitempty"`     // RFC 3339 date for Sunset header
	UpstreamPath string `json:"upstream_path,omitempty"`   // Override upstream path for this version
}
