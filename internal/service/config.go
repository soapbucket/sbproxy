// Package service manages the HTTP server lifecycle including graceful shutdown and TLS configuration.
package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/soapbucket/sbproxy/internal/request/classifier"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/platform/storage"
)

const (
	configName      = "sb"
	configEnvPrefix = "sb"

	// defaultMinTLS is set to TLS 1.3 for security (TLS 1.2 has known vulnerabilities)
	// Use explicit opt-in for TLS 1.2 if needed
	defaultMinTLS = 13
)

// Config is an alias for ServerConfig for backward compatibility

var globalConfig Config

func init() {

	globalConfig = Config{
		ProxyConfig: ProxyConfig{
			HTTPBindPort:  8080,
			HTTPSBindPort: 8443,
			BindAddress:   "127.0.0.1",
			ReadTimeout:   5 * time.Second,
			WriteTimeout:  10 * time.Second,
			IdleTimeout:   15 * time.Second,
			GraceTime:     30 * time.Second,

			CompressionLevel:  5,
			MaxRecursionDepth: 5,

			OriginLoaderSettings: OriginLoaderSettings{
				MaxOriginRecursionDepth:   10,
				MaxOriginForwardDepth:     10,
				OriginCacheTTL:            5 * time.Minute,
				HostnameFallback:          true,
				HostFilterEnabled:         true,
				HostFilterEstimatedItems:  10000,
				HostFilterFPRate:          0.001,
				HostFilterRebuildInterval: 1 * time.Hour,
				HostFilterRebuildJitter:   0.1,
			},

			ConfigSyncMode:           "hybrid",
			OriginCacheRefreshTopic:  "origin_cache_refresh",
			EnableOriginCacheRefresh: false,
			ProxyConfigChangesTopic:  "proxy-config-changes",
			EnableProxyConfigChanges: true, // Enable by default to receive messages from proxy-admin

			ResponseCacheExpirationTopic:  "response_cache_expiration",
			EnableResponseCacheExpiration: false,
			ResponseCacheNormalizeURL:     true,
			ResponseCacheNormalizePath:    true,
			ResponseCacheDefaultMethod:    "GET",

			SignatureCacheExpirationTopic:  "signature_cache_expiration",
			EnableSignatureCacheExpiration: false,
			SignatureCacheNormalizeURL:     true,
			SignatureCacheNormalizePath:    true,
			SignatureCacheDefaultMethod:    "GET",

			SessionCacherSettings: SessionCacherSettings{
				SessionCookieName: "_sb.s",
				SessionMaxAge:     3600,
				L2CacheTimeout:    5 * time.Minute,
			},

			StickyCookieSettings: StickyCookieSettings{
				StickyCookieName:     "_sb.l",
				StickyCookieDuration: 1 * time.Hour,
			},

			DebugSettings: DebugSettings{
				Debug:          false,
				DisplayHeaders: false,
			},

			DNSCacheSettings: DNSCacheSettings{
				Enabled:           true,
				MaxEntries:        10000,
				DefaultTTL:        300 * time.Second,
				NegativeTTL:       60 * time.Second,
				ServeStaleOnError: true,
				BackgroundRefresh: true,
			},

			HTTP2Coalescing: HTTP2CoalescingSettings{
				Disabled:                 false,            // Enabled by default (per OPTIMIZATIONS.md #14)
				MaxIdleConnsPerHost:      20,               // Increased from 10 (per proposal)
				IdleConnTimeout:          90 * time.Second, // Match HTTP client defaults
				MaxConnLifetime:          1 * time.Hour,    // Maximum connection lifetime
				AllowIPBasedCoalescing:   true,             // Enable IP-based coalescing
				AllowCertBasedCoalescing: true,             // Enable cert-based coalescing
				StrictCertValidation:     false,            // Non-strict by default for better coalescing
			},

			RequestCoalescing: RequestCoalescingSettings{
				Enabled:         false,                  // Disabled by default (opt-in per OPTIMIZATIONS.md #10)
				MaxInflight:     1000,                   // Maximum in-flight coalesced requests
				CoalesceWindow:  100 * time.Millisecond, // Time window for coalescing
				MaxWaiters:      100,                    // Maximum waiters per request
				CleanupInterval: 30 * time.Second,       // Cleanup interval for stale entries
				KeyStrategy:     "default",              // Default key generation strategy
			},

			CertificateSettings: CertificateSettings{
				CertificateDir:         "certs",
				CertificateKeyDir:      "certs",
				MinTLSVersion:          defaultMinTLS,
				TLSCipherSuites:        []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
				UseACME:                false,
				ACMEEmail:              "",
				ACMEDomains:            []string{},
				ACMECacheDir:           "acme-cache",
				ACMEDirectoryURL:       "",    // Empty = Let's Encrypt production
				ACMEInsecureSkipVerify: false, // Only enable for testing with Pebble
			},

			LoggingConfig: LoggingConfig{
				Format: "", // Empty means auto-detect from APP_ENV
			},
		},
		TelemetryConfig: TelemetryConfig{
			BindPort:        8888,
			BindAddress:     "127.0.0.1",
			EnableProfiler:  false,
			MinTLSVersion:   defaultMinTLS,
			TLSCipherSuites: []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		},

		OTelConfig: OTelConfig{
			Enabled:      false,
			ServiceName:  "soapbucket-proxy",
			SampleRate:   1.0,
			Environment:  "development",
			OTLPEndpoint: "localhost:4317",
			OTLPProtocol: "grpc",
			OTLPInsecure: true,
		},
	}

	viper.SetEnvPrefix(configEnvPrefix)
	replacer := strings.NewReplacer(".", "__")
	viper.SetEnvKeyReplacer(replacer)
	viper.SetConfigName(configName)
	setViperDefaults()
	viper.AutomaticEnv()
	viper.AllowEmptyEnv(true)
}

// stringToModelsDurationHookFunc returns a mapstructure decode hook that converts
// string values (e.g., "2s", "5m") to reqctx.Duration structs.
func stringToModelsDurationHookFunc() mapstructure.DecodeHookFunc {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String {
			return data, nil
		}
		if t != reflect.TypeOf(reqctx.Duration{}) {
			return data, nil
		}
		d, err := time.ParseDuration(reqctx.ExpandDays(data.(string)))
		if err != nil {
			return nil, fmt.Errorf("invalid duration %q: %w", data, err)
		}
		return reqctx.Duration{Duration: d}, nil
	}
}

// LoadConfig loads the configuration from file and environment variables
func LoadConfig(configDir, configFile string) error {
	viper.AddConfigPath(configDir)
	setViperAdditionalConfigPaths()
	viper.AddConfigPath(".")
	setConfigFile(configDir, configFile)
	if err := viper.ReadInConfig(); err != nil {
		// if the user specifies a configuration file we get os.ErrNotExist.
		// viper.ConfigFileNotFoundError is returned if viper is unable
		// to find sb.{json,yaml, etc..} in any of the search paths
		if errors.As(err, &viper.ConfigFileNotFoundError{}) {
			slog.Debug("no configuration file found")
		} else {
			slog.Warn("error loading configuration file", "error", err)
			metric.ConfigError("global", "file_read_error")
		}
	}
	err := viper.Unmarshal(&globalConfig, viper.DecodeHook(
		mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			stringToModelsDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
		),
	))
	if err != nil {
		slog.Warn("error parsing configuration file", "error", err)
		metric.ConfigError("global", "parse_error")
		return err
	}
	slog.Debug("config file used", "file", viper.ConfigFileUsed())

	// Apply config section if present (unified config.origins or config.source)
	if err := applyConfigSection(); err != nil {
		return err
	}

	// Fix viper key mangling: viper treats dots in map keys as path separators,
	// so "echo.test.local" becomes {"echo": {"test": {"local": ...}}}.
	// Re-read origins from the raw config to preserve hostname keys with dots.
	if err := fixOriginHostnameKeys(); err != nil {
		slog.Warn("failed to fix origin hostname keys from raw config", "error", err)
	}

	// Support env override for server variables (viper has trouble with map env binding)
	if globalConfig.Var == nil {
		globalConfig.Var = make(map[string]string)
	}
	if v := os.Getenv("SB_VAR__API_BASE_URL"); v != "" {
		globalConfig.Var["api_base_url"] = v
	}

	// Fix: If storage driver is postgres, ensure params only contains dsn (not path)
	// Viper merges map values, so we need to clean up params when switching drivers
	if globalConfig.StorageSettings.Driver == "postgres" {
		if globalConfig.StorageSettings.Params == nil {
			globalConfig.StorageSettings.Params = make(map[string]string)
		}
		// Always remove path param for postgres driver (postgres uses dsn, not path)
		delete(globalConfig.StorageSettings.Params, "path")
		// Check if dsn is set via environment variable (viper might not have unmarshaled it correctly)
		if dsn := viper.GetString("storage_settings.params.dsn"); dsn != "" {
			globalConfig.StorageSettings.Params["dsn"] = dsn
		}
		// If still no dsn, check direct env var
		if _, hasDSN := globalConfig.StorageSettings.Params["dsn"]; !hasDSN {
			if dsn := os.Getenv("SB_STORAGE_SETTINGS__PARAMS__DSN"); dsn != "" {
				globalConfig.StorageSettings.Params["dsn"] = dsn
			}
		}
	}

	// Fix: Ensure L3 cache (pebble) uses absolute path from env var if set
	if globalConfig.L3CacheSettings.Driver == "pebble" {
		if globalConfig.L3CacheSettings.Params == nil {
			globalConfig.L3CacheSettings.Params = make(map[string]string)
		}
		// Check if path is set via environment variable (overrides YAML)
		if path := viper.GetString("l3_cache_settings.params.path"); path != "" {
			globalConfig.L3CacheSettings.Params["path"] = path
		} else if path := os.Getenv("SB_L3_CACHE_SETTINGS__PARAMS__PATH"); path != "" {
			globalConfig.L3CacheSettings.Params["path"] = path
		}
		// Ensure path is absolute (pebble needs absolute path)
		if path, ok := globalConfig.L3CacheSettings.Params["path"]; ok && path != "" && !filepath.IsAbs(path) {
			// Convert relative path to absolute based on working directory
			if absPath, err := filepath.Abs(path); err == nil {
				globalConfig.L3CacheSettings.Params["path"] = absPath
			}
		}
	}

	// Debug: Log what was loaded for storage_settings
	slog.Debug("storage settings loaded",
		"driver", globalConfig.StorageSettings.Driver,
		"has_params", len(globalConfig.StorageSettings.Params) > 0,
		"params", globalConfig.StorageSettings.Params,
		"viper_dsn", viper.GetString("storage_settings.params.dsn"),
		"env_dsn", os.Getenv("SB_STORAGE_SETTINGS__PARAMS__DSN"))

	return nil
}

func setConfigFile(configDir, configFile string) {
	if configFile == "" {
		return
	}
	if !filepath.IsAbs(configFile) && reqctx.IsFileInputValid(configFile) {
		configFile = filepath.Join(configDir, configFile)
	}
	viper.SetConfigFile(configFile)
}

func setViperDefaults() {
	viper.SetDefault("telemetry.bind_port", globalConfig.TelemetryConfig.BindPort)
	viper.SetDefault("telemetry.bind_address", globalConfig.TelemetryConfig.BindAddress)
	viper.SetDefault("telemetry.enable_profiler", globalConfig.TelemetryConfig.EnableProfiler)
	viper.SetDefault("telemetry.certificate_file", globalConfig.TelemetryConfig.CertificateFile)
	viper.SetDefault("telemetry.certificate_key_file", globalConfig.TelemetryConfig.CertificateKeyFile)
	viper.SetDefault("telemetry.min_tls_version", globalConfig.TelemetryConfig.MinTLSVersion)
	viper.SetDefault("telemetry.tls_cipher_suites", globalConfig.TelemetryConfig.TLSCipherSuites)

	// OpenTelemetry defaults
	viper.SetDefault("otel.enabled", globalConfig.OTelConfig.Enabled)
	viper.SetDefault("otel.service_name", globalConfig.OTelConfig.ServiceName)
	viper.SetDefault("otel.service_version", globalConfig.OTelConfig.ServiceVersion)
	viper.SetDefault("otel.otlp_endpoint", globalConfig.OTelConfig.OTLPEndpoint)
	viper.SetDefault("otel.otlp_protocol", globalConfig.OTelConfig.OTLPProtocol)
	viper.SetDefault("otel.otlp_insecure", globalConfig.OTelConfig.OTLPInsecure)
	viper.SetDefault("otel.sample_rate", globalConfig.OTelConfig.SampleRate)
	viper.SetDefault("otel.environment", globalConfig.OTelConfig.Environment)

	viper.SetDefault("proxy.http_bind_port", globalConfig.ProxyConfig.HTTPBindPort)
	viper.SetDefault("proxy.https_bind_port", globalConfig.ProxyConfig.HTTPSBindPort)
	viper.SetDefault("proxy.http3_bind_port", globalConfig.ProxyConfig.HTTP3BindPort)
	viper.SetDefault("proxy.enable_http3", globalConfig.ProxyConfig.EnableHTTP3)
	viper.SetDefault("proxy.bind_address", globalConfig.ProxyConfig.BindAddress)
	viper.SetDefault("proxy.read_timeout", globalConfig.ProxyConfig.ReadTimeout)
	viper.SetDefault("proxy.write_timeout", globalConfig.ProxyConfig.WriteTimeout)
	viper.SetDefault("proxy.idle_timeout", globalConfig.ProxyConfig.IdleTimeout)
	viper.SetDefault("proxy.compression_level", globalConfig.ProxyConfig.CompressionLevel)
	viper.SetDefault("proxy.max_recursion_depth", globalConfig.ProxyConfig.MaxRecursionDepth)
	viper.SetDefault("proxy.grace_time", globalConfig.ProxyConfig.GraceTime)

	viper.SetDefault("https_proxy.disable_http2_connect", globalConfig.HTTPSProxyConfig.DisableHTTP2Connect)
	viper.SetDefault("https_proxy.disable_http3_connect", globalConfig.HTTPSProxyConfig.DisableHTTP3Connect)
	viper.SetDefault("https_proxy.enable_rfc8441_websocket", globalConfig.HTTPSProxyConfig.EnableRFC8441WebSocket)
	viper.SetDefault("https_proxy.enable_connect_udp", globalConfig.HTTPSProxyConfig.EnableConnectUDP)
	viper.SetDefault("https_proxy.enable_connect_ip", globalConfig.HTTPSProxyConfig.EnableConnectIP)
	viper.SetDefault("https_proxy.connect_udp_template", globalConfig.HTTPSProxyConfig.ConnectUDPTemplate)

	viper.SetDefault("proxy.certificate_settings.certificate_dir", globalConfig.ProxyConfig.CertificateSettings.CertificateDir)
	viper.SetDefault("proxy.certificate_settings.certificate_key_dir", globalConfig.ProxyConfig.CertificateSettings.CertificateKeyDir)
	viper.SetDefault("proxy.certificate_settings.min_tls_version", globalConfig.ProxyConfig.CertificateSettings.MinTLSVersion)
	viper.SetDefault("proxy.certificate_settings.tls_cipher_suites", globalConfig.ProxyConfig.CertificateSettings.TLSCipherSuites)
	viper.SetDefault("proxy.certificate_settings.use_acme", globalConfig.ProxyConfig.CertificateSettings.UseACME)
	viper.SetDefault("proxy.certificate_settings.acme_email", globalConfig.ProxyConfig.CertificateSettings.ACMEEmail)
	viper.SetDefault("proxy.certificate_settings.acme_domains", globalConfig.ProxyConfig.CertificateSettings.ACMEDomains)
	viper.SetDefault("proxy.certificate_settings.acme_cache_dir", globalConfig.ProxyConfig.CertificateSettings.ACMECacheDir)
	viper.SetDefault("proxy.certificate_settings.acme_directory_url", globalConfig.ProxyConfig.CertificateSettings.ACMEDirectoryURL)
	viper.SetDefault("proxy.certificate_settings.acme_insecure_skip_verify", globalConfig.ProxyConfig.CertificateSettings.ACMEInsecureSkipVerify)

	// Logging defaults
	viper.SetDefault("proxy.logging.format", globalConfig.ProxyConfig.LoggingConfig.Format)

	// Session defaults (not OAuth specific) - these are in SessionCacherSettings
	viper.SetDefault("proxy.session_cacher_settings.session_cookie_name", globalConfig.ProxyConfig.SessionCacherSettings.SessionCookieName)
	viper.SetDefault("proxy.session_cacher_settings.session_max_age", globalConfig.ProxyConfig.SessionCacherSettings.SessionMaxAge)
	viper.SetDefault("proxy.session_cacher_settings.session_l2_cache_timeout", globalConfig.ProxyConfig.SessionCacherSettings.L2CacheTimeout)

	// Load balancer sticky session defaults (not OAuth specific) - this is in StickyCookieSettings
	viper.SetDefault("proxy.sticky_cookie_settings.sticky_cookie_name", globalConfig.ProxyConfig.StickyCookieSettings.StickyCookieName)
	viper.SetDefault("proxy.sticky_cookie_settings.sticky_cookie_duration", globalConfig.ProxyConfig.StickyCookieSettings.StickyCookieDuration)

	// Origin loader defaults (not OAuth specific) - this is in OriginLoaderSettings
	viper.SetDefault("proxy.origin_loader_settings.max_origin_recursion_depth", globalConfig.ProxyConfig.OriginLoaderSettings.MaxOriginRecursionDepth)
	viper.SetDefault("proxy.origin_loader_settings.max_origin_forward_depth", globalConfig.ProxyConfig.OriginLoaderSettings.MaxOriginForwardDepth)
	viper.SetDefault("proxy.origin_loader_settings.origin_cache_ttl", globalConfig.ProxyConfig.OriginLoaderSettings.OriginCacheTTL)
	viper.SetDefault("proxy.origin_loader_settings.hostname_fallback", globalConfig.ProxyConfig.OriginLoaderSettings.HostnameFallback)
	viper.SetDefault("proxy.origin_loader_settings.host_filter_enabled", globalConfig.ProxyConfig.OriginLoaderSettings.HostFilterEnabled)
	viper.SetDefault("proxy.origin_loader_settings.host_filter_estimated_items", globalConfig.ProxyConfig.OriginLoaderSettings.HostFilterEstimatedItems)
	viper.SetDefault("proxy.origin_loader_settings.host_filter_fp_rate", globalConfig.ProxyConfig.OriginLoaderSettings.HostFilterFPRate)
	viper.SetDefault("proxy.origin_loader_settings.host_filter_rebuild_interval", globalConfig.ProxyConfig.OriginLoaderSettings.HostFilterRebuildInterval)
	viper.SetDefault("proxy.origin_loader_settings.host_filter_rebuild_jitter", globalConfig.ProxyConfig.OriginLoaderSettings.HostFilterRebuildJitter)

	// Config sync mode: push, pull, or hybrid
	viper.SetDefault("proxy.config_sync_mode", globalConfig.ProxyConfig.ConfigSyncMode)

	// Origin cache refresh defaults
	viper.SetDefault("proxy.origin_cache_refresh_topic", globalConfig.ProxyConfig.OriginCacheRefreshTopic)
	viper.SetDefault("proxy.enable_origin_cache_refresh", globalConfig.ProxyConfig.EnableOriginCacheRefresh)
	viper.SetDefault("proxy.proxy_config_changes_topic", globalConfig.ProxyConfig.ProxyConfigChangesTopic)
	viper.SetDefault("proxy.enable_proxy_config_changes", globalConfig.ProxyConfig.EnableProxyConfigChanges)

	// Response cache expiration defaults
	viper.SetDefault("proxy.response_cache_expiration_topic", globalConfig.ProxyConfig.ResponseCacheExpirationTopic)
	viper.SetDefault("proxy.enable_response_cache_expiration", globalConfig.ProxyConfig.EnableResponseCacheExpiration)
	viper.SetDefault("proxy.response_cache_normalize_url", globalConfig.ProxyConfig.ResponseCacheNormalizeURL)
	viper.SetDefault("proxy.response_cache_normalize_path", globalConfig.ProxyConfig.ResponseCacheNormalizePath)
	viper.SetDefault("proxy.response_cache_default_method", globalConfig.ProxyConfig.ResponseCacheDefaultMethod)

	// Signature cache expiration defaults
	viper.SetDefault("proxy.signature_cache_expiration_topic", globalConfig.ProxyConfig.SignatureCacheExpirationTopic)
	viper.SetDefault("proxy.enable_signature_cache_expiration", globalConfig.ProxyConfig.EnableSignatureCacheExpiration)
	viper.SetDefault("proxy.signature_cache_normalize_url", globalConfig.ProxyConfig.SignatureCacheNormalizeURL)
	viper.SetDefault("proxy.signature_cache_normalize_path", globalConfig.ProxyConfig.SignatureCacheNormalizePath)
	viper.SetDefault("proxy.signature_cache_default_method", globalConfig.ProxyConfig.SignatureCacheDefaultMethod)

	viper.SetDefault("proxy.debug_settings.debug", globalConfig.ProxyConfig.DebugSettings.Debug)
	viper.SetDefault("proxy.debug_settings.display_headers", globalConfig.ProxyConfig.DebugSettings.DisplayHeaders)

	viper.SetDefault("proxy.dns_cache.enabled", globalConfig.ProxyConfig.DNSCacheSettings.Enabled)
	viper.SetDefault("proxy.dns_cache.max_entries", globalConfig.ProxyConfig.DNSCacheSettings.MaxEntries)
	viper.SetDefault("proxy.dns_cache.default_ttl", globalConfig.ProxyConfig.DNSCacheSettings.DefaultTTL)
	viper.SetDefault("proxy.dns_cache.negative_ttl", globalConfig.ProxyConfig.DNSCacheSettings.NegativeTTL)
	viper.SetDefault("proxy.dns_cache.serve_stale_on_error", globalConfig.ProxyConfig.DNSCacheSettings.ServeStaleOnError)
	viper.SetDefault("proxy.dns_cache.background_refresh", globalConfig.ProxyConfig.DNSCacheSettings.BackgroundRefresh)

	// HTTP/2 coalescing defaults (per OPTIMIZATIONS.md #14)
	viper.SetDefault("proxy.http2_coalescing.disabled", globalConfig.ProxyConfig.HTTP2Coalescing.Disabled)
	viper.SetDefault("proxy.http2_coalescing.max_idle_conns_per_host", globalConfig.ProxyConfig.HTTP2Coalescing.MaxIdleConnsPerHost)
	viper.SetDefault("proxy.http2_coalescing.idle_conn_timeout", globalConfig.ProxyConfig.HTTP2Coalescing.IdleConnTimeout)
	viper.SetDefault("proxy.http2_coalescing.max_conn_lifetime", globalConfig.ProxyConfig.HTTP2Coalescing.MaxConnLifetime)
	viper.SetDefault("proxy.http2_coalescing.allow_ip_based_coalescing", globalConfig.ProxyConfig.HTTP2Coalescing.AllowIPBasedCoalescing)
	viper.SetDefault("proxy.http2_coalescing.allow_cert_based_coalescing", globalConfig.ProxyConfig.HTTP2Coalescing.AllowCertBasedCoalescing)
	viper.SetDefault("proxy.http2_coalescing.strict_cert_validation", globalConfig.ProxyConfig.HTTP2Coalescing.StrictCertValidation)

	// Request coalescing defaults (per OPTIMIZATIONS.md #10)
	viper.SetDefault("proxy.request_coalescing.enabled", globalConfig.ProxyConfig.RequestCoalescing.Enabled)
	viper.SetDefault("proxy.request_coalescing.max_inflight", globalConfig.ProxyConfig.RequestCoalescing.MaxInflight)
	viper.SetDefault("proxy.request_coalescing.coalesce_window", globalConfig.ProxyConfig.RequestCoalescing.CoalesceWindow)
	viper.SetDefault("proxy.request_coalescing.max_waiters", globalConfig.ProxyConfig.RequestCoalescing.MaxWaiters)
	viper.SetDefault("proxy.request_coalescing.cleanup_interval", globalConfig.ProxyConfig.RequestCoalescing.CleanupInterval)
	viper.SetDefault("proxy.request_coalescing.key_strategy", globalConfig.ProxyConfig.RequestCoalescing.KeyStrategy)

	// Classifier sidecar defaults (local_llm in sb.yml)
	viper.SetDefault("local_llm.pool_size", 4)
	viper.SetDefault("local_llm.timeout", "2s")
	viper.SetDefault("local_llm.ready_timeout", "10s")
	viper.SetDefault("local_llm.fail_open", true)
	viper.SetDefault("local_llm.rate_limit.requests_per_second", 100.0)
	viper.SetDefault("local_llm.rate_limit.burst", 50)
	viper.SetDefault("local_llm.embedding_cache.max_entries", 10000)
	viper.SetDefault("local_llm.embedding_cache.ttl", "5m")

	viper.SetDefault("crypto.driver", globalConfig.CryptoSettings.Driver)
	viper.SetDefault("crypto.params", globalConfig.CryptoSettings.Params)
	viper.SetDefault("crypto.enable_metrics", globalConfig.CryptoSettings.EnableMetrics)
	viper.SetDefault("crypto.enable_tracing", globalConfig.CryptoSettings.EnableTracing)

	viper.SetDefault("storage_settings.driver", globalConfig.StorageSettings.Driver)
	viper.SetDefault("storage_settings.params", globalConfig.StorageSettings.Params)
	viper.SetDefault("storage_settings.enable_metrics", globalConfig.StorageSettings.EnableMetrics)
	viper.SetDefault("storage_settings.enable_tracing", globalConfig.StorageSettings.EnableTracing)

	viper.SetDefault("l1_cache_settings.driver", globalConfig.L1CacheSettings.Driver)
	viper.SetDefault("l1_cache_settings.params", globalConfig.L1CacheSettings.Params)
	viper.SetDefault("l1_cache_settings.enable_metrics", globalConfig.L1CacheSettings.EnableMetrics)
	viper.SetDefault("l1_cache_settings.enable_tracing", globalConfig.L1CacheSettings.EnableTracing)

	viper.SetDefault("l2_cache_settings.driver", globalConfig.L2CacheSettings.Driver)
	viper.SetDefault("l2_cache_settings.params", globalConfig.L2CacheSettings.Params)
	viper.SetDefault("l2_cache_settings.enable_metrics", globalConfig.L2CacheSettings.EnableMetrics)
	viper.SetDefault("l2_cache_settings.enable_tracing", globalConfig.L2CacheSettings.EnableTracing)

	viper.SetDefault("l3_cache_settings.driver", globalConfig.L3CacheSettings.Driver)
	viper.SetDefault("l3_cache_settings.params", globalConfig.L3CacheSettings.Params)
	viper.SetDefault("l3_cache_settings.enable_metrics", globalConfig.L3CacheSettings.EnableMetrics)
	viper.SetDefault("l3_cache_settings.enable_tracing", globalConfig.L3CacheSettings.EnableTracing)

	viper.SetDefault("messenger.driver", globalConfig.MessengerSettings.Driver)
	viper.SetDefault("messenger.params", globalConfig.MessengerSettings.Params)
	viper.SetDefault("messenger.enable_metrics", globalConfig.MessengerSettings.EnableMetrics)
	viper.SetDefault("messenger.enable_tracing", globalConfig.MessengerSettings.EnableTracing)

	viper.SetDefault("event_settings.driver", globalConfig.EventSettings.Driver)
	viper.SetDefault("event_settings.params", globalConfig.EventSettings.Params)
	viper.SetDefault("event_settings.enable_metrics", globalConfig.EventSettings.EnableMetrics)
	viper.SetDefault("event_settings.enable_tracing", globalConfig.EventSettings.EnableTracing)

	viper.SetDefault("geoip.driver", globalConfig.GeoIPSettings.Driver)
	viper.SetDefault("geoip.params", globalConfig.GeoIPSettings.Params)
	viper.SetDefault("geoip.enable_metrics", globalConfig.GeoIPSettings.EnableMetrics)
	viper.SetDefault("geoip.enable_tracing", globalConfig.GeoIPSettings.EnableTracing)

	viper.SetDefault("uaparser.driver", globalConfig.UAParserSettings.Driver)
	viper.SetDefault("uaparser.params", globalConfig.UAParserSettings.Params)
	viper.SetDefault("uaparser.enable_metrics", globalConfig.UAParserSettings.EnableMetrics)
	viper.SetDefault("uaparser.enable_tracing", globalConfig.UAParserSettings.EnableTracing)

}

// GetClassifierSettings returns the classifier sidecar settings from the global config.
func GetClassifierSettings() classifier.Settings {
	return globalConfig.ClassifierSettings
}

// GetGlobalHTTP2CoalescingConfig returns the global HTTP/2 coalescing configuration
func GetGlobalHTTP2CoalescingConfig() HTTP2CoalescingSettings {
	return globalConfig.ProxyConfig.HTTP2Coalescing
}

// GetGlobalRequestCoalescingConfig returns the global request coalescing configuration
func GetGlobalRequestCoalescingConfig() RequestCoalescingSettings {
	return globalConfig.ProxyConfig.RequestCoalescing
}

func setViperAdditionalConfigPaths() {
	viper.AddConfigPath("$HOME/.config/sb")
	viper.AddConfigPath("/etc/sb")
}

// applyConfigSection applies the config section when present.
// Option 1: config.origins - inline sites; sets globalConfig.Origins and storage to local.
// Option 2: config.source - external location; sets globalConfig.StorageSettings.
// When both are present, origins takes precedence.
func applyConfigSection() error {
	if globalConfig.Config == nil {
		return nil
	}
	cfg := globalConfig.Config

	// Option 1: Inline origins
	if len(cfg.Origins) > 0 {
		globalConfig.Origins = cfg.Origins
		if globalConfig.StorageSettings.Driver == "" {
			globalConfig.StorageSettings.Driver = storage.DriverLocal
		} else if globalConfig.StorageSettings.Driver != storage.DriverLocal {
			// Wrap existing driver as composite secondary
			compositeParams := make(map[string]string, len(globalConfig.StorageSettings.Params)+1)
			compositeParams["secondary_driver"] = globalConfig.StorageSettings.Driver
			for k, v := range globalConfig.StorageSettings.Params {
				compositeParams["secondary_"+k] = v
			}
			globalConfig.StorageSettings = storage.Settings{
				Driver:        storage.DriverComposite,
				Params:        compositeParams,
				EnableMetrics: globalConfig.StorageSettings.EnableMetrics,
				EnableTracing: globalConfig.StorageSettings.EnableTracing,
			}
		}
		slog.Debug("config section applied", "mode", "inline", "origins_count", len(cfg.Origins))
		return nil
	}

	// Option 2: External source
	if cfg.Source != nil {
		settings := configSourceToStorageSettings(cfg.Source)
		if settings.Driver != "" {
			globalConfig.StorageSettings = settings
			if globalConfig.StorageSettings.Params == nil {
				globalConfig.StorageSettings.Params = make(map[string]string)
			}
			globalConfig.Origins = nil // External source; do not use inline origins
			slog.Debug("config section applied", "mode", "source", "driver", settings.Driver)
		}
	}
	return nil
}

// fixOriginHostnameKeys re-reads the config file to extract origin hostname keys
// with dots preserved. Viper treats dots as path separators, mangling keys like
// "echo.test.local" into nested maps. This function reads the raw YAML to get
// the correct keys and rebuilds globalConfig.Origins.
func fixOriginHostnameKeys() error {
	configFile := viper.ConfigFileUsed()
	if configFile == "" {
		return nil
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	// Parse the raw YAML to extract origin keys with dots preserved
	var raw struct {
		Config *struct {
			Origins map[string]map[string]any `yaml:"origins"`
		} `yaml:"config"`
		Origins map[string]map[string]any `yaml:"origins"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse config file: %w", err)
	}

	// Determine which origins map to use
	origins := raw.Origins
	if raw.Config != nil && len(raw.Config.Origins) > 0 {
		origins = raw.Config.Origins
	}

	if len(origins) == 0 {
		return nil
	}

	// Only fix if the keys actually differ (viper mangled them)
	if len(origins) == len(globalConfig.Origins) {
		allMatch := true
		for k := range origins {
			if _, ok := globalConfig.Origins[k]; !ok {
				allMatch = false
				break
			}
		}
		if allMatch {
			return nil
		}
	}

	globalConfig.Origins = origins
	slog.Debug("fixed origin hostname keys from raw config", "hostname_count", len(origins))

	// Re-apply storage driver setting if needed
	if globalConfig.StorageSettings.Driver == "" {
		globalConfig.StorageSettings.Driver = storage.DriverLocal
	}

	return nil
}

// configSourceToStorageSettings converts ConfigSource to storage.Settings.
// Handles path (file) and url (http) shorthands.
func configSourceToStorageSettings(src *ConfigSource) storage.Settings {
	if src == nil {
		return storage.Settings{}
	}
	params := make(map[string]string)
	if src.Params != nil {
		for k, v := range src.Params {
			params[k] = v
		}
	}
	driver := src.Driver

	// Shorthand: path -> file driver
	if src.Path != "" {
		driver = storage.DriverFile
		params[storage.ParamPath] = src.Path
	}
	// Shorthand: url -> http driver
	if src.URL != "" {
		driver = "http"
		params["url"] = src.URL
	}

	return storage.Settings{
		Driver:        driver,
		Params:        params,
		EnableMetrics: true,
		EnableTracing: true,
	}
}

// loadLocalOrigins converts globalConfig.Origins (parsed from sb.yaml) into JSON bytes
// and seeds the local storage driver. No-op if Origins is empty.
func loadLocalOrigins() error {
	if len(globalConfig.Origins) == 0 {
		return nil
	}

	origins := make(map[string][]byte, len(globalConfig.Origins))
	for hostname, configMap := range globalConfig.Origins {
		jsonBytes, err := json.Marshal(configMap)
		if err != nil {
			return fmt.Errorf("service: marshal local origin %q: %w", hostname, err)
		}
		origins[hostname] = jsonBytes
	}
	storage.SetLocalOrigins(origins)

	switch globalConfig.StorageSettings.Driver {
	case "":
		globalConfig.StorageSettings.Driver = storage.DriverLocal
	case storage.DriverLocal:
		// already local, no change
	default:
		// Wrap existing driver as composite secondary
		compositeParams := make(map[string]string, len(globalConfig.StorageSettings.Params)+1)
		compositeParams["secondary_driver"] = globalConfig.StorageSettings.Driver
		for k, v := range globalConfig.StorageSettings.Params {
			compositeParams["secondary_"+k] = v
		}
		globalConfig.StorageSettings = storage.Settings{
			Driver: storage.DriverComposite,
			Params: compositeParams,
		}
	}
	return nil
}

// LoadNewConfig loads the new configuration structure from a YAML file
func LoadNewConfig(configPath string) (*Config, error) {
	cfg := &Config{}

	// Create a new viper instance for this config
	v := viper.New()
	v.SetConfigFile(configPath)
	v.SetConfigType("yaml")

	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}

	if err := v.Unmarshal(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
