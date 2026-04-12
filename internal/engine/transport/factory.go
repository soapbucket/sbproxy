// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/platform/circuitbreaker"
	pkgtransport "github.com/soapbucket/sbproxy/pkg/transport"
)

// globalHTTP2CoalescingGetter is an optional hook set by internal/config so that
// NewTransportFromConfig can inherit global HTTP/2 coalescing settings.
// If nil, sensible defaults are used.
var globalHTTP2CoalescingGetter func() HTTP2CoalescingConfig

// SetGlobalHTTP2CoalescingGetter registers the getter called by NewTransportFromConfig.
// Call this from service initialization (before first request).
func SetGlobalHTTP2CoalescingGetter(fn func() HTTP2CoalescingConfig) {
	globalHTTP2CoalescingGetter = fn
}

// globalRequestCoalescingGetter is analogous to globalHTTP2CoalescingGetter for request coalescing.
var globalRequestCoalescingGetter func() CoalescingConfig

// SetGlobalRequestCoalescingGetter registers the getter for global request coalescing config.
func SetGlobalRequestCoalescingGetter(fn func() CoalescingConfig) {
	globalRequestCoalescingGetter = fn
}

// NewTransportFromConfig creates an http.RoundTripper from a public ConnectionConfig.
// It replicates the logic of internal/config.ClientConnectionTransportFn without any
// dependency on internal/config types.
//
// originURL, if provided, is used as a hint for the health-check manager; pass the
// upstream origin URL (e.g., "https://api.example.com") when available.
func NewTransportFromConfig(cfg pkgtransport.ConnectionConfig, originURL ...string) http.RoundTripper {
	// Apply production-sensible defaults for zero values.
	idleConn := cfg.IdleConnTimeout
	if idleConn == 0 {
		idleConn = 90 * time.Second
	}
	tlsHS := cfg.TLSHandshakeTimeout
	if tlsHS == 0 {
		tlsHS = 10 * time.Second
	}
	dial := cfg.DialTimeout
	if dial == 0 {
		dial = 10 * time.Second
	}
	keepAlive := cfg.KeepAlive
	if keepAlive == 0 {
		keepAlive = 90 * time.Second
	}

	// Build the base transport.
	baseTransport := NewHTTPTransportWithOptions(
		idleConn,
		tlsHS,
		dial,
		keepAlive,
		cfg.SkipTLSVerifyHost,
		cfg.HTTP11Only,
		&httputil.HTTPTransportOptions{
			MaxIdleConns:          cfg.MaxIdleConns,
			MaxIdleConnsPerHost:   cfg.MaxIdleConnsPerHost,
			MaxConnsPerHost:       cfg.MaxConnsPerHost,
			ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
			ExpectContinueTimeout: cfg.ExpectContinueTimeout,
			DisableCompression:    cfg.DisableCompression,
			DisableKeepAlives:     false,
			WriteBufferSize:       cfg.WriteBufferSize,
			ReadBufferSize:        cfg.ReadBufferSize,
			EnableHTTP3:           &cfg.EnableHTTP3,
			MinTLSVersion:         cfg.MinTLSVersion,
			MTLSClientCertFile:    cfg.MTLSClientCertFile,
			MTLSClientKeyFile:     cfg.MTLSClientKeyFile,
			MTLSCACertFile:        cfg.MTLSCACertFile,
			MTLSClientCertData:    cfg.MTLSClientCertData,
			MTLSClientKeyData:     cfg.MTLSClientKeyData,
			MTLSCACertData:        cfg.MTLSCACertData,
		},
	)

	var tr http.RoundTripper = baseTransport

	// Apply HTTP/2 coalescing (enabled by default unless HTTP/1.1-only or HTTP/3).
	if !cfg.HTTP11Only && !cfg.EnableHTTP3 {
		coalescingCfg := mergeHTTP2CoalescingConfig(cfg.HTTP2Coalescing)
		if coalescingCfg.Enabled {
			tlsConfig := &tls.Config{
				InsecureSkipVerify: cfg.SkipTLSVerifyHost, //nolint:gosec
			}
			tr = NewHTTP2CoalescingTransport(coalescingCfg, tlsConfig)
		}
	}

	// Apply request coalescing.
	requestCfg := mergeRequestCoalescingConfig(cfg.RequestCoalescing)
	if requestCfg.Enabled {
		tr = NewCoalescingTransport(tr, requestCfg)
	}

	// Rate limiting.
	if cfg.RateLimit > 0 {
		tr = NewRateLimiter(tr, cfg.RateLimit, cfg.BurstLimit)
	}

	// Connection limiting.
	if cfg.MaxConnections > 0 {
		tr = NewMaxConnections(tr, cfg.MaxConnections)
	}

	// Redirect handling.
	if !cfg.DisableFollowRedirects {
		maxRedirects := cfg.MaxRedirects
		if maxRedirects == 0 {
			maxRedirects = 5
		}
		tr = NewRedirecter(tr, maxRedirects)
	}

	// Transport wrappers (hedging, circuit breaker, retry, health check).
	if cfg.TransportWrappers != nil {
		wrappers := cfg.TransportWrappers

		if wrappers.Hedging != nil && wrappers.Hedging.Enabled {
			delay := wrappers.Hedging.Delay
			if delay == 0 {
				delay = 100 * time.Millisecond
			}
			maxHedges := wrappers.Hedging.MaxHedges
			if maxHedges == 0 {
				maxHedges = 1
			}
			maxCostRatio := wrappers.Hedging.MaxCostRatio
			if maxCostRatio == 0 {
				maxCostRatio = 0.2
			}
			hedgingCfg := HedgingConfig{
				Enabled:             true,
				Delay:               delay,
				MaxHedges:           maxHedges,
				PercentileThreshold: wrappers.Hedging.PercentileThreshold,
				Methods:             wrappers.Hedging.Methods,
				MaxCostRatio:        maxCostRatio,
			}
			if ht, err := NewHedgingTransport(tr, hedgingCfg); err == nil {
				tr = ht
			}
		}

		if wrappers.CircuitBreaker != nil && wrappers.CircuitBreaker.Enabled {
			cbCfg := circuitbreaker.Config{
				FailureThreshold: uint32(wrappers.CircuitBreaker.FailureThreshold),
				SuccessThreshold: uint32(wrappers.CircuitBreaker.SuccessThreshold),
				Timeout:          wrappers.CircuitBreaker.Timeout,
			}
			// Use origin URL as the breaker name for per-origin isolation.
			name := "transport"
			if len(originURL) > 0 && originURL[0] != "" {
				name = originURL[0]
			}
			tr = NewCircuitBreakerTransport(tr, name, cbCfg)
		}

		if wrappers.Retry != nil && wrappers.Retry.Enabled {
			maxRetries := wrappers.Retry.MaxRetries
			if maxRetries == 0 {
				maxRetries = 3
			}
			rt := NewRetryTransport(tr, maxRetries)
			rt.InitialDelay = wrappers.Retry.InitialDelay
			if rt.InitialDelay == 0 {
				rt.InitialDelay = 100 * time.Millisecond
			}
			rt.MaxDelay = wrappers.Retry.MaxDelay
			if rt.MaxDelay == 0 {
				rt.MaxDelay = 10 * time.Second
			}
			rt.BackoffMultiplier = wrappers.Retry.Multiplier
			if rt.BackoffMultiplier == 0 {
				rt.BackoffMultiplier = 2.0
			}
			rt.Jitter = wrappers.Retry.Jitter
			if rt.Jitter == 0 {
				rt.Jitter = 0.1
			}
			if len(wrappers.Retry.RetryableStatus) > 0 {
				rt.RetryableStatusCodes = wrappers.Retry.RetryableStatus
			}
			tr = rt
		}

		// Health check: wrap with a HealthCheckTransport that gates requests on
		// periodic upstream liveness probes.
		if wrappers.HealthCheck != nil && wrappers.HealthCheck.Enabled {
			target := ""
			if len(originURL) > 0 {
				target = originURL[0]
			}
			if target != "" {
				endpoint := wrappers.HealthCheck.Endpoint
				if endpoint == "" {
					endpoint = "/"
				}
				interval := wrappers.HealthCheck.Interval
				if interval == 0 {
					interval = 10 * time.Second
				}
				timeout := wrappers.HealthCheck.Timeout
				if timeout == 0 {
					timeout = 5 * time.Second
				}
				healthyThreshold := wrappers.HealthCheck.HealthyThreshold
				if healthyThreshold == 0 {
					healthyThreshold = 2
				}
				unhealthyThreshold := wrappers.HealthCheck.UnhealthyThreshold
				if unhealthyThreshold == 0 {
					unhealthyThreshold = 3
				}
				expectedStatus := wrappers.HealthCheck.ExpectedStatus
				if expectedStatus == 0 {
					expectedStatus = 200
				}
				hcCfg := &HealthCheckConfig{
					Endpoint:           endpoint,
					Interval:           interval,
					Timeout:            timeout,
					HealthyThreshold:   healthyThreshold,
					UnhealthyThreshold: unhealthyThreshold,
					ExpectedStatus:     expectedStatus,
				}
				if wrappers.HealthCheck.Type != "" {
					hcCfg.Type = HealthCheckType(wrappers.HealthCheck.Type)
				}
				if wrappers.HealthCheck.Host != "" {
					hcCfg.Host = wrappers.HealthCheck.Host
				}
				if wrappers.HealthCheck.ExpectedBody != "" {
					hcCfg.ExpectedBody = wrappers.HealthCheck.ExpectedBody
				}
				hc := NewHealthChecker(target, hcCfg)
				hc.Start()
				tr = &HealthCheckTransport{Base: tr, HealthChecker: hc}
			}
		}
	}

	return tr
}

// mergeHTTP2CoalescingConfig returns a merged HTTP2CoalescingConfig from global defaults
// and per-origin overrides.
func mergeHTTP2CoalescingConfig(override *pkgtransport.HTTP2CoalescingOverride) HTTP2CoalescingConfig {
	// Start with global default (or hardcoded sensible defaults).
	cfg := HTTP2CoalescingConfig{
		Enabled:                  true,
		MaxIdleConnsPerHost:      20,
		IdleConnTimeout:          90 * time.Second,
		MaxConnLifetime:          1 * time.Hour,
		AllowIPBasedCoalescing:   true,
		AllowCertBasedCoalescing: true,
		StrictCertValidation:     false,
	}
	if globalHTTP2CoalescingGetter != nil {
		cfg = globalHTTP2CoalescingGetter()
	}

	if override == nil {
		return cfg
	}

	cfg.Enabled = !override.Disabled
	if override.MaxIdleConnsPerHost > 0 {
		cfg.MaxIdleConnsPerHost = override.MaxIdleConnsPerHost
	}
	if override.IdleConnTimeout > 0 {
		cfg.IdleConnTimeout = override.IdleConnTimeout
	}
	if override.MaxConnLifetime > 0 {
		cfg.MaxConnLifetime = override.MaxConnLifetime
	}
	cfg.AllowIPBasedCoalescing = override.AllowIPBasedCoalescing
	cfg.AllowCertBasedCoalescing = override.AllowCertBasedCoalescing
	cfg.StrictCertValidation = override.StrictCertValidation

	return cfg
}

// mergeRequestCoalescingConfig returns a merged CoalescingConfig from global defaults
// and per-origin overrides.
func mergeRequestCoalescingConfig(override *pkgtransport.RequestCoalescingOverride) CoalescingConfig {
	cfg := CoalescingConfig{
		Enabled:         false,
		MaxInflight:     1000,
		CoalesceWindow:  100 * time.Millisecond,
		MaxWaiters:      100,
		CleanupInterval: 30 * time.Second,
		KeyFunc:         DefaultCoalesceKey,
	}
	if globalRequestCoalescingGetter != nil {
		cfg = globalRequestCoalescingGetter()
	}

	if override == nil {
		return cfg
	}

	cfg.Enabled = override.Enabled
	if override.MaxInflight > 0 {
		cfg.MaxInflight = override.MaxInflight
	}
	if override.CoalesceWindow > 0 {
		cfg.CoalesceWindow = override.CoalesceWindow
	}
	if override.MaxWaiters > 0 {
		cfg.MaxWaiters = override.MaxWaiters
	}
	if override.CleanupInterval > 0 {
		cfg.CleanupInterval = override.CleanupInterval
	}
	if override.KeyStrategy != "" {
		switch override.KeyStrategy {
		case "method_url":
			cfg.KeyFunc = MethodURLKey
		default:
			cfg.KeyFunc = DefaultCoalesceKey
		}
	}

	return cfg
}
