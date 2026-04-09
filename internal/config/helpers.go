// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/engine/transport"
)

// Global health check manager (can be set by service initialization)
var globalHealthCheckManager *HealthCheckManager

// SetHealthCheckManager sets the global health check manager
func SetHealthCheckManager(mgr *HealthCheckManager) {
	globalHealthCheckManager = mgr
}

// Global HTTP/2 coalescing config (can be set by service initialization)
// This avoids import cycle: config -> service -> configloader -> config
var globalHTTP2CoalescingConfigGetter func() transport.HTTP2CoalescingConfig

// SetHTTP2CoalescingConfigGetter sets the function to get global HTTP/2 coalescing config
func SetHTTP2CoalescingConfigGetter(getter func() transport.HTTP2CoalescingConfig) {
	globalHTTP2CoalescingConfigGetter = getter
}

// Global request coalescing config (can be set by service initialization)
// This avoids import cycle: config -> service -> configloader -> config
var globalRequestCoalescingConfigGetter func() transport.CoalescingConfig

// SetRequestCoalescingConfigGetter sets the function to get global request coalescing config
func SetRequestCoalescingConfigGetter(getter func() transport.CoalescingConfig) {
	globalRequestCoalescingConfigGetter = getter
}

// Global ClickHouse config getter for subsystems that write to separate tables
// (e.g., AI memory writer). Set by service initialization.
var globalClickHouseConfigGetter func() *ClickHouseConfig

// SetClickHouseConfigGetter sets the function to get ClickHouse connection config.
func SetClickHouseConfigGetter(getter func() *ClickHouseConfig) {
	globalClickHouseConfigGetter = getter
}

// GetGlobalClickHouseConfig returns the global ClickHouse config, or nil.
func GetGlobalClickHouseConfig() *ClickHouseConfig {
	if globalClickHouseConfigGetter != nil {
		return globalClickHouseConfigGetter()
	}
	return nil
}

// Define the StructToMap function as provided
func StructToMap(obj any) map[string]any {
	result := make(map[string]any)
	val := reflect.ValueOf(obj)

	// If obj is a pointer, dereference it
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	// Only proceed if it's a struct
	if val.Kind() != reflect.Struct {
		return result
	}

	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)
		fieldVal := val.Field(i)

		// Skip unexported fields (they cause panic when calling Interface())
		if !fieldVal.CanInterface() {
			continue
		}

		// Get the JSON tag
		jsonTag := field.Tag.Get("json")
		if jsonTag == "-" { // Skip if the tag is "-"
			continue
		}

		// Extract the actual JSON key (before the comma, if any)
		keys := strings.SplitN(jsonTag, ",", 2)
		key := keys[0]
		if key == "" { // If no JSON tag or empty, use the field name
			key = field.Name
		}

		if len(keys) > 1 {
			omitempty := keys[1] == "omitempty"
			if omitempty {
				// Only call IsNil() on types that support it (pointer, slice, map, chan, func, interface)
				kind := fieldVal.Kind()
				if kind == reflect.Ptr || kind == reflect.Slice || kind == reflect.Map ||
					kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface {
					if fieldVal.IsNil() {
						continue
					}
				} else {
					// For other types (strings, ints, etc.), check if zero value
					if fieldVal.IsZero() {
						continue
					}
				}
			}
		}

		// Handle nested structs recursively
		// Note: fieldVal.CanSet() is usually for modifying the value.
		// For reading, you only need to ensure it's a struct.
		if fieldVal.Kind() == reflect.Struct {
			result[key] = StructToMap(fieldVal.Interface())
		} else {
			result[key] = fieldVal.Interface()
		}
	}
	return result
}

// ClientConnectionTransportFn is a variable for client connection transport fn.
var ClientConnectionTransportFn = func(connCfg *BaseConnection, originURL ...string) http.RoundTripper {
	// Create base transport
	baseTransport := transport.NewHTTPTransportWithOptions(
		connCfg.IdleConnTimeout.Duration,
		connCfg.TLSHandshakeTimeout.Duration,
		connCfg.DialTimeout.Duration,
		connCfg.KeepAlive.Duration,
		connCfg.SkipTLSVerifyHost,
		connCfg.HTTP11Only,

		&httputil.HTTPTransportOptions{
			MaxIdleConns:          connCfg.MaxIdleConns,
			MaxIdleConnsPerHost:   connCfg.MaxIdleConnsPerHost,
			MaxConnsPerHost:       connCfg.MaxConnsPerHost,
			ResponseHeaderTimeout: connCfg.ResponseHeaderTimeout.Duration,
			ExpectContinueTimeout: connCfg.ExpectContinueTimeout.Duration,
			DisableCompression:    connCfg.DisableCompression,
			DisableKeepAlives:     false,
			WriteBufferSize:       connCfg.WriteBufferSize,
			ReadBufferSize:        connCfg.ReadBufferSize,
			EnableHTTP3:           &connCfg.EnableHTTP3,
			MinTLSVersion:         connCfg.MinTLSVersion,
			// Pass mTLS configuration
			MTLSClientCertFile: connCfg.MTLSClientCertFile,
			MTLSClientKeyFile:  connCfg.MTLSClientKeyFile,
			MTLSCACertFile:     connCfg.MTLSCACertFile,
			MTLSClientCertData: connCfg.MTLSClientCertData,
			MTLSClientKeyData:  connCfg.MTLSClientKeyData,
			MTLSCACertData:     connCfg.MTLSCACertData,
		},
	)

	// Apply HTTP/2 coalescing if enabled (per OPTIMIZATIONS.md #14).
	// Skip coalescing when HTTP/3 is explicitly enabled because the base transport
	// is already an HTTP/3 transport and should not be replaced by an HTTP/2 path.
	var tr http.RoundTripper = baseTransport
	if !connCfg.HTTP11Only && !connCfg.EnableHTTP3 {
		// Get merged config (global defaults + per-origin overrides)
		coalescingConfig := getHTTP2CoalescingConfig(connCfg)
		
		// Apply coalescing if not disabled (enabled by default)
		if coalescingConfig.Enabled {
			// Create TLS config for coalescing transport
			tlsConfig := &tls.Config{
				InsecureSkipVerify: connCfg.SkipTLSVerifyHost,
			}
			
			// Wrap with HTTP/2 coalescing transport
			coalescingTransport := transport.NewHTTP2CoalescingTransport(
				transport.HTTP2CoalescingConfig{
					Enabled:                  coalescingConfig.Enabled,
					MaxIdleConnsPerHost:      coalescingConfig.MaxIdleConnsPerHost,
					IdleConnTimeout:          coalescingConfig.IdleConnTimeout,
					MaxConnLifetime:          coalescingConfig.MaxConnLifetime,
					AllowIPBasedCoalescing:   coalescingConfig.AllowIPBasedCoalescing,
					AllowCertBasedCoalescing: coalescingConfig.AllowCertBasedCoalescing,
					StrictCertValidation:     coalescingConfig.StrictCertValidation,
				},
				tlsConfig,
			)
			tr = coalescingTransport
		}
	}

	// Apply request coalescing if enabled (per OPTIMIZATIONS.md #10)
	// Get merged config (global defaults + per-origin overrides)
	requestCoalescingConfig := getRequestCoalescingConfig(connCfg)
	if requestCoalescingConfig.Enabled {
		tr = transport.NewCoalescingTransport(tr, requestCoalescingConfig)
	}

	// Wrap with middleware (order matters - outer wrappers execute first)

	// Apply rate limiting if configured
	if connCfg.RateLimit > 0 {
		tr = transport.NewRateLimiter(tr, connCfg.RateLimit, connCfg.BurstLimit)
	}

	// Apply connection limiting if configured
	if connCfg.MaxConnections > 0 {
		tr = transport.NewConnectionLimiter(tr, connCfg.MaxConnections)
	}

	// Apply redirect handling if not disabled
	if !connCfg.DisableFollowRedirects {
		maxRedirects := connCfg.MaxRedirects
		if maxRedirects == 0 {
			maxRedirects = 5 // Default
		}
		tr = transport.NewRedirecter(tr, maxRedirects)
	}

	// Apply transport wrappers if configured (new unified approach)
	// Order matters: outer wrappers execute first
	// Health Check -> Hedging -> Retry -> Base Transport
	if connCfg.TransportWrappers != nil {
		wrappers := connCfg.TransportWrappers

		// Apply health check wrapper (outermost - checks health before sending)
		if wrappers.HealthCheck != nil && wrappers.HealthCheck.Enabled {
			// Get origin URL from parameter or use empty string (will be determined from request)
			url := ""
			if len(originURL) > 0 {
				url = originURL[0]
			}
			tr = &healthCheckTransportWrapper{
				Base:      tr,
				Config:    wrappers.HealthCheck,
				Manager:   globalHealthCheckManager,
				OriginURL: url,
			}
		}

		// Apply hedging wrapper
		if wrappers.Hedging != nil && wrappers.Hedging.Enabled {
			hedgingConfig := transport.HedgingConfig{
				Enabled:            true,
				Delay:              wrappers.Hedging.Delay.Duration,
				MaxHedges:          wrappers.Hedging.MaxHedges,
				PercentileThreshold: wrappers.Hedging.PercentileThreshold,
				Methods:            wrappers.Hedging.Methods,
				MaxCostRatio:       wrappers.Hedging.MaxCostRatio,
			}
			// Set defaults
			if hedgingConfig.Delay == 0 {
				hedgingConfig.Delay = 100 * time.Millisecond
			}
			if hedgingConfig.MaxHedges == 0 {
				hedgingConfig.MaxHedges = 1
			}
			if hedgingConfig.MaxCostRatio == 0 {
				hedgingConfig.MaxCostRatio = 0.2
			}
			hedgingTransport, err := transport.NewHedgingTransport(tr, hedgingConfig)
			if err == nil {
				tr = hedgingTransport
			}
		}

		// Apply retry wrapper (innermost - retries after base transport)
		if wrappers.Retry != nil && wrappers.Retry.Enabled {
			maxRetries := wrappers.Retry.MaxRetries
			if maxRetries == 0 {
				maxRetries = 3
			}
			retryTransport := transport.NewRetryTransport(tr, maxRetries)
			retryTransport.InitialDelay = wrappers.Retry.InitialDelay.Duration
			if retryTransport.InitialDelay == 0 {
				retryTransport.InitialDelay = 100 * time.Millisecond
			}
			retryTransport.MaxDelay = wrappers.Retry.MaxDelay.Duration
			if retryTransport.MaxDelay == 0 {
				retryTransport.MaxDelay = 10 * time.Second
			}
			retryTransport.BackoffMultiplier = wrappers.Retry.Multiplier
			if retryTransport.BackoffMultiplier == 0 {
				retryTransport.BackoffMultiplier = 2.0
			}
			retryTransport.Jitter = wrappers.Retry.Jitter
			if retryTransport.Jitter == 0 {
				retryTransport.Jitter = 0.1
			}
			if len(wrappers.Retry.RetryableStatus) > 0 {
				retryTransport.RetryableStatusCodes = wrappers.Retry.RetryableStatus
			}
			tr = retryTransport
		}
	}

	return tr
}

// getHTTP2CoalescingConfig merges global HTTP/2 coalescing config with per-origin overrides
// Returns merged config with global defaults as fallback for unset per-origin values
func getHTTP2CoalescingConfig(connCfg *BaseConnection) transport.HTTP2CoalescingConfig {
	// Get global config via getter (avoids import cycle)
	var globalConfig transport.HTTP2CoalescingConfig
	if globalHTTP2CoalescingConfigGetter != nil {
		globalConfig = globalHTTP2CoalescingConfigGetter()
	} else {
		// Default values if getter not set (shouldn't happen in production)
		globalConfig = transport.HTTP2CoalescingConfig{
			Enabled:                  true, // Enabled by default
			MaxIdleConnsPerHost:      20,
			IdleConnTimeout:          90 * time.Second,
			MaxConnLifetime:          1 * time.Hour,
			AllowIPBasedCoalescing:   true,
			AllowCertBasedCoalescing: true,
			StrictCertValidation:     false,
		}
	}
	
	// Start with global defaults
	config := globalConfig
	
	// Apply per-origin overrides if present
	if connCfg.HTTP2Coalescing != nil {
		override := connCfg.HTTP2Coalescing
		
		// Disabled: if HTTP2Coalescing is present, use its Disabled value
		// Convert to Enabled for transport config (inverted)
		config.Enabled = !override.Disabled
		
		// Merge numeric/duration fields (use override if non-zero, otherwise keep global default)
		if override.MaxIdleConnsPerHost > 0 {
			config.MaxIdleConnsPerHost = override.MaxIdleConnsPerHost
		}
		if override.IdleConnTimeout.Duration > 0 {
			config.IdleConnTimeout = override.IdleConnTimeout.Duration
		}
		if override.MaxConnLifetime.Duration > 0 {
			config.MaxConnLifetime = override.MaxConnLifetime.Duration
		}
		
		// Boolean fields: Since we can't distinguish between "not set" and "false",
		// we use a convention: if HTTP2Coalescing struct exists, use override values.
		// This means if user sets http2_coalescing: {}, booleans will be false (zero value).
		// To override booleans, user must explicitly set them.
		// Note: This is a limitation - we can't tell if false was explicitly set or default.
		// In practice, if user wants to override booleans, they'll set them explicitly.
		config.AllowIPBasedCoalescing = override.AllowIPBasedCoalescing
		config.AllowCertBasedCoalescing = override.AllowCertBasedCoalescing
		config.StrictCertValidation = override.StrictCertValidation
	}
	
	return config
}

// getRequestCoalescingConfig merges global request coalescing config with per-origin overrides
// Returns merged config with global defaults as fallback for unset per-origin values
func getRequestCoalescingConfig(connCfg *BaseConnection) transport.CoalescingConfig {
	// Get global config via getter (avoids import cycle)
	var globalConfig transport.CoalescingConfig
	if globalRequestCoalescingConfigGetter != nil {
		globalConfig = globalRequestCoalescingConfigGetter()
	} else {
		// Default values if getter not set (shouldn't happen in production)
		globalConfig = transport.CoalescingConfig{
			Enabled:         false, // Disabled by default (opt-in)
			MaxInflight:     1000,
			CoalesceWindow:  100 * time.Millisecond,
			MaxWaiters:      100,
			CleanupInterval: 30 * time.Second,
			KeyFunc:         transport.DefaultCoalesceKey,
		}
	}

	// Start with global defaults
	config := globalConfig

	// Apply per-origin overrides if present
	if connCfg.RequestCoalescing != nil {
		override := connCfg.RequestCoalescing

		// Enabled: if RequestCoalescing is present, use its Enabled value
		config.Enabled = override.Enabled

		// Merge numeric/duration fields (use override if non-zero, otherwise keep global default)
		if override.MaxInflight > 0 {
			config.MaxInflight = override.MaxInflight
		}
		if override.CoalesceWindow.Duration > 0 {
			config.CoalesceWindow = override.CoalesceWindow.Duration
		}
		if override.MaxWaiters > 0 {
			config.MaxWaiters = override.MaxWaiters
		}
		if override.CleanupInterval.Duration > 0 {
			config.CleanupInterval = override.CleanupInterval.Duration
		}

		// Key strategy: use override if set, otherwise keep global default
		if override.KeyStrategy != "" {
			config.KeyFunc = getCoalesceKeyFunc(override.KeyStrategy)
		}
	}

	return config
}

// getCoalesceKeyFunc returns the appropriate key function based on strategy
func getCoalesceKeyFunc(strategy string) transport.CoalesceKeyFunc {
	switch strategy {
	case "method_url":
		return transport.MethodURLKey
	case "default":
		fallthrough
	default:
		return transport.DefaultCoalesceKey
	}
}

// healthCheckTransportWrapper wraps a transport with health checking
// It dynamically gets the health checker based on the origin URL
type healthCheckTransportWrapper struct {
	Base      http.RoundTripper
	Config    *TransportHealthCheckConfig
	Manager   *HealthCheckManager
	OriginURL string // Origin URL from config (e.g., "https://api.example.com")
}

// RoundTrip performs the round trip operation on the healthCheckTransportWrapper.
func (t *healthCheckTransportWrapper) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Manager == nil || t.Config == nil {
		// No health check manager or config, pass through
		return t.Base.RoundTrip(req)
	}

	// Determine origin URL - prefer configured URL, fallback to request URL
	originURL := t.OriginURL
	if originURL == "" {
		originURL = req.URL.String()
		if req.URL.Scheme == "" || req.URL.Host == "" {
			// Fallback: try to construct from request
			scheme := "https"
			if req.TLS == nil {
				scheme = "http"
			}
			originURL = scheme + "://" + req.Host
		}
	}

	// Use origin URL as key for health checker
	key := originURL

	// Get or create health checker for this origin
	checker, err := t.Manager.GetOrCreateHealthChecker(key, originURL, t.Config)
	if err != nil {
		// Log error but continue
		return t.Base.RoundTrip(req)
	}

	if checker == nil {
		// Health check not enabled or failed to create, pass through
		return t.Base.RoundTrip(req)
	}

	// Check if backend is healthy
	if !checker.IsHealthy() {
		return nil, &healthCheckError{message: "backend is unhealthy"}
	}

	return t.Base.RoundTrip(req)
}

// healthCheckError represents a health check failure
type healthCheckError struct {
	message string
}

// Error performs the error operation on the healthCheckError.
func (e *healthCheckError) Error() string {
	return e.message
}

// StaticTransportFn is a variable for static transport fn.
var StaticTransportFn = func(cfg *StaticConfig) TransportFn {
	return func(req *http.Request) (*http.Response, error) {
		if cfg.StatusCode == 0 {
			cfg.StatusCode = http.StatusOK
		}

		resp := &http.Response{
			StatusCode: cfg.StatusCode,
			Header:     make(http.Header),
			Request:    req,
		}

		// Set content type with default if not specified
		contentType := cfg.ContentType
		if contentType == "" {
			contentType = "text/plain; charset=utf-8"
		}
		resp.Header.Set("Content-Type", contentType)

		// Set custom headers (if any)
		for key, value := range cfg.Headers {
			resp.Header.Set(key, value)
		}

		// Priority order: BodyBase64 > JSONBody > Body
		switch {
		case cfg.BodyBase64 != "":
			body, err := base64.StdEncoding.DecodeString(cfg.BodyBase64)
			if err != nil {
				return nil, err
			}
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
		case cfg.JSONBody != nil:
			// json.RawMessage is already marshaled JSON, use it directly
			resp.Body = io.NopCloser(bytes.NewReader(cfg.JSONBody))
			resp.ContentLength = int64(len(cfg.JSONBody))
		case cfg.Body != "":
			body := strings.NewReader(cfg.Body)
			resp.Body = io.NopCloser(body)
			resp.ContentLength = int64(len(cfg.Body))
		default:
			resp.Body = http.NoBody
			resp.ContentLength = 0
		}

		return resp, nil
	}
}
