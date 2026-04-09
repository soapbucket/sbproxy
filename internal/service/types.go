// Package service manages the HTTP server lifecycle including graceful shutdown and TLS configuration.
package service

import (
	"time"

	"github.com/soapbucket/sbproxy/internal/config"
	"github.com/soapbucket/sbproxy/internal/app/billing"
	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/request/classifier"
	"github.com/soapbucket/sbproxy/internal/security/crypto"
	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/request/geoip"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
	"github.com/soapbucket/sbproxy/internal/cache/origin"
	"github.com/soapbucket/sbproxy/internal/platform/storage"
	"github.com/soapbucket/sbproxy/internal/request/uaparser"
)

// TelemetryConfig holds configuration for telemetry.
type TelemetryConfig struct {
	Enabled            bool     `yaml:"enabled" mapstructure:"enabled"`
	BindAddress        string   `yaml:"bind_address" mapstructure:"bind_address"`
	BindPort           int      `yaml:"bind_port" mapstructure:"bind_port"`
	TLSCert            string   `yaml:"tls_cert" mapstructure:"tls_cert"`
	TLSKey             string   `yaml:"tls_key" mapstructure:"tls_key"`
	CertificateFile    string   `yaml:"certificate_file" mapstructure:"certificate_file"`
	CertificateKeyFile string   `yaml:"certificate_key_file" mapstructure:"certificate_key_file"`
	EnableProfiler     bool     `yaml:"enable_profiler" mapstructure:"enable_profiler"`
	MinTLSVersion      int      `yaml:"min_tls_version" mapstructure:"min_tls_version"`
	TLSCipherSuites    []string `yaml:"tls_cipher_suites" mapstructure:"tls_cipher_suites"`
}

// OTelConfig holds configuration for OpenTelemetry.
type OTelConfig struct {
	Enabled        bool     `yaml:"enabled" mapstructure:"enabled"`
	OTLPEndpoint   string   `yaml:"otlp_endpoint" mapstructure:"otlp_endpoint"`
	OTLPProtocol   string   `yaml:"otlp_protocol" mapstructure:"otlp_protocol"`
	OTLPInsecure   bool     `yaml:"otlp_insecure" mapstructure:"otlp_insecure"`
	ServiceName    string   `yaml:"service_name" mapstructure:"service_name"`
	ServiceVersion string   `yaml:"service_version" mapstructure:"service_version"`
	Environment    string   `yaml:"environment" mapstructure:"environment"`
	SampleRate     float64  `yaml:"sample_rate" mapstructure:"sample_rate"`
	Headers        []string `yaml:"headers,omitempty" mapstructure:"headers,omitempty"`
}

// CertificateSettings represents TLS certificate configuration
type CertificateSettings struct {
	CertificateDir    string   `yaml:"certificate_dir" mapstructure:"certificate_dir"`
	CertificateKeyDir string   `yaml:"certificate_key_dir" mapstructure:"certificate_key_dir"`
	MinTLSVersion     int      `yaml:"min_tls_version" mapstructure:"min_tls_version"`
	TLSCipherSuites   []string `yaml:"tls_cipher_suites" mapstructure:"tls_cipher_suites"`
	UseACME           bool     `yaml:"use_acme" mapstructure:"use_acme"`
	ACMEEmail         string   `yaml:"acme_email" mapstructure:"acme_email"`
	ACMEDomains       []string `yaml:"acme_domains" mapstructure:"acme_domains"`
	ACMECacheDir      string   `yaml:"acme_cache_dir" mapstructure:"acme_cache_dir"`
	// ACMEDirectoryURL allows using a custom ACME directory (e.g., Let's Encrypt staging, Pebble test server)
	// If empty, defaults to Let's Encrypt production
	// Examples:
	//   - Let's Encrypt Staging: https://acme-staging-v02.api.letsencrypt.org/directory
	//   - Pebble test server: https://localhost:14000/dir
	ACMEDirectoryURL string `yaml:"acme_directory_url" mapstructure:"acme_directory_url"`
	// ACMEInsecureSkipVerify disables TLS certificate verification when connecting to ACME server
	// Only use for testing with self-signed certificates (e.g., Pebble)
	ACMEInsecureSkipVerify bool `yaml:"acme_insecure_skip_verify" mapstructure:"acme_insecure_skip_verify"`
	// ACMECACertFile is the path to a PEM-encoded CA certificate file for the ACME server
	// Used when the ACME server uses a self-signed or custom CA (e.g., Pebble)
	ACMECACertFile string `yaml:"acme_ca_cert_file" mapstructure:"acme_ca_cert_file"`

	// ClientAuth sets the mTLS client authentication policy for inbound connections.
	// Supported values: "none" (default), "request", "require", "verify_if_given", "require_and_verify".
	ClientAuth string `yaml:"client_auth" mapstructure:"client_auth"`
	// ClientCACertFile is the path to a PEM-encoded CA certificate bundle used to verify client certificates.
	// Required when ClientAuth is set to any value other than "none".
	ClientCACertFile string `yaml:"client_ca_cert_file" mapstructure:"client_ca_cert_file"`
	// ClientCACertData is a base64-encoded CA certificate bundle (alternative to ClientCACertFile).
	ClientCACertData string `yaml:"client_ca_cert_data" mapstructure:"client_ca_cert_data"`
}

// OriginLoaderSettings represents origin loader configuration
type OriginLoaderSettings struct {
	MaxOriginRecursionDepth   int           `yaml:"max_origin_recursion_depth" mapstructure:"max_origin_recursion_depth"`
	MaxOriginForwardDepth     int           `yaml:"max_origin_forward_depth" mapstructure:"max_origin_forward_depth"`
	OriginCacheTTL            time.Duration `yaml:"origin_cache_ttl" mapstructure:"origin_cache_ttl"`
	HostnameFallback          bool          `yaml:"hostname_fallback" mapstructure:"hostname_fallback"`
	HostFilterEnabled         bool          `yaml:"host_filter_enabled" mapstructure:"host_filter_enabled"`
	HostFilterEstimatedItems  int           `yaml:"host_filter_estimated_items" mapstructure:"host_filter_estimated_items"`
	HostFilterFPRate          float64       `yaml:"host_filter_fp_rate" mapstructure:"host_filter_fp_rate"`
	HostFilterRebuildInterval time.Duration `yaml:"host_filter_rebuild_interval" mapstructure:"host_filter_rebuild_interval"`
	HostFilterRebuildJitter   float64       `yaml:"host_filter_rebuild_jitter" mapstructure:"host_filter_rebuild_jitter"`
}

// SessionCacherSettings holds configuration for session cacher.
type SessionCacherSettings struct {
	SessionCookieName string        `yaml:"session_cookie_name" mapstructure:"session_cookie_name"`
	SessionMaxAge     int           `yaml:"session_max_age" mapstructure:"session_max_age"`
	L2CacheTimeout    time.Duration `yaml:"session_l2_cache_timeout" mapstructure:"session_l2_cache_timeout"`
}

// StickyCookieSettings holds configuration for sticky cookie.
type StickyCookieSettings struct {
	StickyCookieName     string        `yaml:"sticky_cookie_name" mapstructure:"sticky_cookie_name"`
	StickyCookieDuration time.Duration `yaml:"sticky_cookie_duration" mapstructure:"sticky_cookie_duration"`
}

// DebugSettings holds configuration for debug.
type DebugSettings struct {
	Debug          bool `yaml:"debug" mapstructure:"debug"`
	DisplayHeaders bool `yaml:"display_headers" mapstructure:"display_headers"`
}

// LoggingConfig holds configuration for logging.
type LoggingConfig struct {
	Format      string                            `yaml:"format" mapstructure:"format"` // "json" or "dev" (colored human-readable)
	Application *logging.ApplicationLoggingConfig `yaml:"application" mapstructure:"application"`
	Request     *logging.RequestLoggingConfig     `yaml:"request" mapstructure:"request"`
	Security    *logging.SecurityLoggingConfig    `yaml:"security" mapstructure:"security"`
}

// DNSCacheSettings holds configuration for dns cache.
type DNSCacheSettings struct {
	Enabled           bool          `yaml:"enabled" mapstructure:"enabled"`
	MaxEntries        int           `yaml:"max_entries" mapstructure:"max_entries"`
	DefaultTTL        time.Duration `yaml:"default_ttl" mapstructure:"default_ttl"`
	NegativeTTL       time.Duration `yaml:"negative_ttl" mapstructure:"negative_ttl"`
	ServeStaleOnError bool          `yaml:"serve_stale_on_error" mapstructure:"serve_stale_on_error"`
	BackgroundRefresh bool          `yaml:"background_refresh" mapstructure:"background_refresh"`
}

// HTTP2CoalescingSettings represents global HTTP/2 connection coalescing configuration
type HTTP2CoalescingSettings struct {
	Disabled                 bool          `yaml:"disabled" mapstructure:"disabled"` // Disable connection coalescing (default: false, meaning enabled by default)
	MaxIdleConnsPerHost      int           `yaml:"max_idle_conns_per_host" mapstructure:"max_idle_conns_per_host"`
	IdleConnTimeout          time.Duration `yaml:"idle_conn_timeout" mapstructure:"idle_conn_timeout"`
	MaxConnLifetime          time.Duration `yaml:"max_conn_lifetime" mapstructure:"max_conn_lifetime"`
	AllowIPBasedCoalescing   bool          `yaml:"allow_ip_based_coalescing" mapstructure:"allow_ip_based_coalescing"`
	AllowCertBasedCoalescing bool          `yaml:"allow_cert_based_coalescing" mapstructure:"allow_cert_based_coalescing"`
	StrictCertValidation     bool          `yaml:"strict_cert_validation" mapstructure:"strict_cert_validation"`
}

// RequestCoalescingSettings represents global request coalescing configuration
type RequestCoalescingSettings struct {
	Enabled         bool          `yaml:"enabled" mapstructure:"enabled"`                   // Enable request coalescing (default: false, opt-in)
	MaxInflight     int           `yaml:"max_inflight" mapstructure:"max_inflight"`         // Maximum in-flight coalesced requests (default: 1000)
	CoalesceWindow  time.Duration `yaml:"coalesce_window" mapstructure:"coalesce_window"`   // Time window for coalescing (default: 100ms)
	MaxWaiters      int           `yaml:"max_waiters" mapstructure:"max_waiters"`           // Maximum waiters per request (default: 100)
	CleanupInterval time.Duration `yaml:"cleanup_interval" mapstructure:"cleanup_interval"` // Cleanup interval for stale entries (default: 30s)
	KeyStrategy     string        `yaml:"key_strategy" mapstructure:"key_strategy"`         // Key generation strategy: "default", "method_url" (default: "default")
}

// HTTPSProxyConfig represents HTTPS proxy port configuration
type HTTPSProxyConfig struct {
	Port               int           `yaml:"port" mapstructure:"port"`                                 // e.g., 3128
	Hostname           string        `yaml:"hostname" mapstructure:"hostname"`                         // e.g., "https-proxy.soapbucket.com"
	CertificateFile    string        `yaml:"certificate_file" mapstructure:"certificate_file"`         // Path to PEM certificate
	CertificateKeyFile string        `yaml:"certificate_key_file" mapstructure:"certificate_key_file"` // Path to PEM key
	AuthRealm          string        `yaml:"auth_realm" mapstructure:"auth_realm"`                     // e.g., "SoapBucket Proxy"
	ReadTimeout        time.Duration `yaml:"read_timeout" mapstructure:"read_timeout"`                 // e.g., "30s"
	WriteTimeout       time.Duration `yaml:"write_timeout" mapstructure:"write_timeout"`               // e.g., "30s"
	IdleTimeout        time.Duration `yaml:"idle_timeout" mapstructure:"idle_timeout"`                 // e.g., "90s"
	DisableHTTP2Connect bool         `yaml:"disable_http2_connect" mapstructure:"disable_http2_connect"`
	DisableHTTP3Connect bool         `yaml:"disable_http3_connect" mapstructure:"disable_http3_connect"`
	EnableRFC8441WebSocket bool      `yaml:"enable_rfc8441_websocket" mapstructure:"enable_rfc8441_websocket"`
	EnableConnectUDP     bool        `yaml:"enable_connect_udp" mapstructure:"enable_connect_udp"`
	EnableConnectIP      bool        `yaml:"enable_connect_ip" mapstructure:"enable_connect_ip"`
	ConnectUDPTemplate   string      `yaml:"connect_udp_template" mapstructure:"connect_udp_template"`
}

// NewProxyConfig represents the simplified proxy configuration from sb.yaml
type ProxyConfig struct {
	HTTPBindPort  int           `yaml:"http_bind_port" mapstructure:"http_bind_port"`
	HTTPSBindPort int           `yaml:"https_bind_port" mapstructure:"https_bind_port"`
	HTTP3BindPort int           `yaml:"http3_bind_port" mapstructure:"http3_bind_port"`
	EnableHTTP3   bool          `yaml:"enable_http3" mapstructure:"enable_http3"`
	BindAddress   string        `yaml:"bind_address" mapstructure:"bind_address"`
	ReadTimeout   time.Duration `yaml:"read_timeout" mapstructure:"read_timeout"`
	WriteTimeout  time.Duration `yaml:"write_timeout" mapstructure:"write_timeout"`
	IdleTimeout   time.Duration `yaml:"idle_timeout" mapstructure:"idle_timeout"`
	GraceTime     time.Duration `yaml:"grace_time" mapstructure:"grace_time"`

	TLSCert string `yaml:"tls_cert" mapstructure:"tls_cert"`
	TLSKey  string `yaml:"tls_key" mapstructure:"tls_key"`

	// Vaults defines server-level vault backends available to all origins.
	// Origin-level vault definitions with the same name override server-level ones.
	Vaults map[string]config.VaultDefinition `yaml:"vaults" mapstructure:"vaults"`

	CompressionLevel  int `yaml:"compression_level" mapstructure:"compression_level"`
	MaxRecursionDepth int `yaml:"max_recursion_depth" mapstructure:"max_recursion_depth"`

	CertificateSettings CertificateSettings `yaml:"certificate_settings" mapstructure:"certificate_settings"`

	LoggingConfig LoggingConfig `yaml:"logging" mapstructure:"logging"`

	OriginLoaderSettings  OriginLoaderSettings      `yaml:"origin_loader_settings" mapstructure:"origin_loader_settings"`
	SessionCacherSettings SessionCacherSettings     `yaml:"session_cacher_settings" mapstructure:"session_cacher_settings"`
	StickyCookieSettings  StickyCookieSettings      `yaml:"sticky_cookie_settings" mapstructure:"sticky_cookie_settings"`
	DebugSettings         DebugSettings             `yaml:"debug_settings" mapstructure:"debug_settings"`
	DNSCacheSettings      DNSCacheSettings          `yaml:"dns_cache" mapstructure:"dns_cache"`
	HTTP2Coalescing       HTTP2CoalescingSettings   `yaml:"http2_coalescing" mapstructure:"http2_coalescing"`
	RequestCoalescing     RequestCoalescingSettings `yaml:"request_coalescing" mapstructure:"request_coalescing"`

	// Config sync mode: "push" (Redis-only), "pull" (REST-only), "hybrid" (both, default).
	// When set to "pull", all message bus subscribers are disabled and the proxy
	// relies exclusively on periodic REST polling for configuration updates.
	ConfigSyncMode string `yaml:"config_sync_mode" mapstructure:"config_sync_mode"`

	// Origin cache refresh via message bus (disabled when ConfigSyncMode is "pull")
	OriginCacheRefreshTopic  string `yaml:"origin_cache_refresh_topic" mapstructure:"origin_cache_refresh_topic"`
	EnableOriginCacheRefresh bool   `yaml:"enable_origin_cache_refresh" mapstructure:"enable_origin_cache_refresh"`
	ProxyConfigChangesTopic  string `yaml:"proxy_config_changes_topic" mapstructure:"proxy_config_changes_topic"`
	EnableProxyConfigChanges bool   `yaml:"enable_proxy_config_changes" mapstructure:"enable_proxy_config_changes"`

	// Response cache expiration via message bus
	ResponseCacheExpirationTopic  string `yaml:"response_cache_expiration_topic" mapstructure:"response_cache_expiration_topic"`
	EnableResponseCacheExpiration bool   `yaml:"enable_response_cache_expiration" mapstructure:"enable_response_cache_expiration"`
	ResponseCacheNormalizeURL     bool   `yaml:"response_cache_normalize_url" mapstructure:"response_cache_normalize_url"`
	ResponseCacheNormalizePath    bool   `yaml:"response_cache_normalize_path" mapstructure:"response_cache_normalize_path"`
	ResponseCacheDefaultMethod    string `yaml:"response_cache_default_method" mapstructure:"response_cache_default_method"`

	// Signature cache expiration via message bus
	SignatureCacheExpirationTopic  string `yaml:"signature_cache_expiration_topic" mapstructure:"signature_cache_expiration_topic"`
	EnableSignatureCacheExpiration bool   `yaml:"enable_signature_cache_expiration" mapstructure:"enable_signature_cache_expiration"`
	SignatureCacheNormalizeURL     bool   `yaml:"signature_cache_normalize_url" mapstructure:"signature_cache_normalize_url"`
	SignatureCacheNormalizePath    bool   `yaml:"signature_cache_normalize_path" mapstructure:"signature_cache_normalize_path"`
	SignatureCacheDefaultMethod    string `yaml:"signature_cache_default_method" mapstructure:"signature_cache_default_method"`

	// AI pricing file path (LiteLLM format JSON) for cost-optimized routing
	AIPricingFile string `yaml:"ai_pricing_file" mapstructure:"ai_pricing_file"`

	// AI providers file path (YAML) for HTTPS proxy AI provider detection
	AIProvidersFile string `yaml:"ai_providers_file" mapstructure:"ai_providers_file"`
}

// NewConfig represents the new configuration structure matching sb.yaml
type Config struct {
	ProxyConfig      ProxyConfig      `yaml:"proxy" mapstructure:"proxy"`
	HTTPSProxyConfig HTTPSProxyConfig `yaml:"https_proxy" mapstructure:"https_proxy"`

	TelemetryConfig TelemetryConfig `yaml:"telemetry" mapstructure:"telemetry"`
	OTelConfig      OTelConfig      `yaml:"otel" mapstructure:"otel"`

	MessengerSettings messenger.Settings `yaml:"messenger_settings" mapstructure:"messenger_settings"`
	EventSettings     messenger.Settings `yaml:"event_settings" mapstructure:"event_settings"`
	GeoIPSettings     geoip.Settings     `yaml:"geoip_settings" mapstructure:"geoip_settings"`
	UAParserSettings  uaparser.Settings  `yaml:"uaparser_settings" mapstructure:"uaparser_settings"`
	StorageSettings   storage.Settings   `yaml:"storage_settings" mapstructure:"storage_settings"`
	CryptoSettings    crypto.Settings    `yaml:"crypto_settings" mapstructure:"crypto_settings"`

	L1CacheSettings cacher.Settings `yaml:"l1_cache_settings" mapstructure:"l1_cache_settings"`
	L2CacheSettings cacher.Settings `yaml:"l2_cache_settings" mapstructure:"l2_cache_settings"`
	L3CacheSettings cacher.Settings `yaml:"l3_cache_settings" mapstructure:"l3_cache_settings"`

	// Var holds operator-defined custom server variables from sb.yml.
	// These are merged into the {{server.*}} template namespace alongside built-in values.
	Var map[string]string `yaml:"var" mapstructure:"var"`

	// Security holds server-level keys (cache encryption, session signing).
	Security SecurityConfig `yaml:"security" mapstructure:"security"`

	// FeatureFlags configures the real-time feature flag system.
	FeatureFlags FeatureFlagConfig `yaml:"feature_flags" mapstructure:"feature_flags"`

	// Billing configures metering writers (ClickHouse, backend HTTP, or both).
	// When omitted, a NoopWriter is used and no billing data is recorded.
	Billing billing.BillingConfig `yaml:"billing" mapstructure:"billing"`

	// ClassifierSettings configures the prompt-classifier sidecar connection.
	// YAML key is "local_llm" to match the user-facing name in sb.yml.
	ClassifierSettings classifier.Settings `yaml:"local_llm" mapstructure:"local_llm"`

	// CacheSystem configures the per-origin key-value cache used by plugins (Lua, WASM).
	// Encryption key, memory limits, and TTL bounds are system-level settings.
	CacheSystem origincache.CacheSystemConfig `yaml:"cache" mapstructure:"cache"`

	// Origins allows defining per-origin configs inline in sb.yaml for local deployments.
	Origins map[string]map[string]any `yaml:"origins" mapstructure:"origins"`

	// Config provides a unified section for origin configuration. Use either:
	// 1. config.origins - inline sites defined directly in sb.yml
	// 2. config.source - external location (file, http, cdb, sqlite, postgres)
	// When present, config overrides top-level storage_settings and origins.
	Config *ConfigSection `yaml:"config" mapstructure:"config"`
}

// ConfigSection defines where origin/sites configuration comes from.
// Option 1: Inline - origins defined directly in sb.yml.
// Option 2: Source - external location (file path, web URL, database, cdb).
type ConfigSection struct {
	// Origins defines sites inline. When non-empty, uses local storage (no external source).
	Origins map[string]map[string]any `yaml:"origins" mapstructure:"origins"`
	// Source defines an external location. Mutually exclusive with origins.
	// Supports shorthand: path (file), url (http). Or full form: driver + params.
	Source *ConfigSource `yaml:"source" mapstructure:"source"`
}

// ConfigSource defines an external config location. Shorthands expand to full storage.Settings.
type ConfigSource struct {
	Driver string            `yaml:"driver" mapstructure:"driver"`
	Params map[string]string `yaml:"params" mapstructure:"params"`
	Path   string            `yaml:"path" mapstructure:"path"`   // Shorthand: path -> driver=file
	URL    string            `yaml:"url" mapstructure:"url"`   // Shorthand: url -> driver=http
}

// SecurityConfig holds server-level security keys loaded once at startup.
// These keys are global to the proxy instance and never appear in origin configs.
type SecurityConfig struct {
	CacheEncryptionKey string `yaml:"cache_encryption_key" mapstructure:"cache_encryption_key" json:"cache_encryption_key"`
	SessionSigningKey  string `yaml:"session_signing_key" mapstructure:"session_signing_key" json:"session_signing_key"`
	AdminAPIKey        string `yaml:"admin_api_key" mapstructure:"admin_api_key" json:"admin_api_key"`
}

// FeatureFlagConfig configures the workspace-scoped feature flag system.
type FeatureFlagConfig struct {
	Enabled       bool           `yaml:"enabled" mapstructure:"enabled"`
	SyncTopic     string         `yaml:"sync_topic" mapstructure:"sync_topic"`
	CacheTTL      time.Duration  `yaml:"cache_ttl" mapstructure:"cache_ttl"`
	DefaultValues map[string]any `yaml:"default_values" mapstructure:"default_values"`
}
