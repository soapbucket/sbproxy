// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"hash/fnv"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	transportpkg "github.com/soapbucket/sbproxy/internal/engine/transport"
)

func init() {
	loaderFns[TypeProxy] = LoadProxy
}

var _ ActionConfig = (*Proxy)(nil)

// Proxy represents a proxy.
type Proxy struct {
	ProxyConfig

	targetURL        *url.URL                        `json:"-"`
	canaryTargetURL  *url.URL                        `json:"-"`
	canaryTransport  http.RoundTripper                `json:"-"`
	shadowTransport  *transportpkg.ShadowTransport    `json:"-"`
}

// Rewrite performs the rewrite operation on the Proxy.
func (p *Proxy) Rewrite() RewriteFn {
	return func(pr *httputil.ProxyRequest) {
		u := pr.In.URL

		// Proxy configs don't need to modify the request structure
		// The actual proxying is done by the transport
		slog.Debug("applying proxy config", "target_url", p.targetURL.String(), "url", u.String())

		// Build the target URL based on StripBasePath setting
		// We set pr.Out.URL directly instead of using SetURL to have full control
		targetURL := &url.URL{
			Scheme: p.targetURL.Scheme,
			Host:   p.targetURL.Host,
		}

		if p.StripBasePath {
			targetURL.Path = u.Path
		} else {
			// Append incoming path to target base path
			// If incoming path is "/" and target URL has a path, use target path only (don't append "/")
			if u.Path == "/" && p.targetURL.Path != "" && p.targetURL.Path != "/" {
				targetURL.Path = p.targetURL.Path
			} else {
				targetURL.Path = p.targetURL.Path + u.Path
			}
		}

		// Handle query parameters based on PreserveQuery setting
		if p.PreserveQuery {
			// Use only the incoming query parameters
			targetURL.RawQuery = u.RawQuery
		} else {
			// Merge query parameters from both incoming request and target URL
			if u.RawQuery != "" || p.targetURL.RawQuery != "" {
				query := p.targetURL.Query()
				for k, vs := range u.Query() {
					for _, v := range vs {
						query.Add(k, v)
					}
				}
				targetURL.RawQuery = query.Encode()
			}
		}

		// Set the URL directly for full control over path handling
		pr.Out.URL = targetURL

		req := pr.Out

		hostname := targetURL.Host

		req.Host = hostname
		req.Header.Set("Host", hostname)

		// alt hostname if we want to set the header to a different hostname
		altHostname := p.AltHostname
		if altHostname != "" {
			req.Host = altHostname
			req.Header.Set("Host", altHostname)
		}

		slog.Debug("setting host", "hostname", hostname, "altHostname", altHostname)

		if p.DisableCompression {
			req.Header.Del("Accept-Encoding")
		} else {
			slog.Debug("enabling compression")
			req.Header.Set("Accept-Encoding", "br, zstd, gzip, deflate, snappy, zlib")
		}

		slog.Debug("modified request for origin", "url", req.URL.String())
	}
}

// Transport returns a transport function that supports canary routing.
// If canary is enabled, a percentage of requests are routed to the canary target.
// Deterministic routing is supported via StickyHeader.
func (p *Proxy) Transport() TransportFn {
	if p.tr == nil {
		return nil
	}

	// If canary is not configured, use the standard transport
	if p.Canary == nil || !p.Canary.Enabled || p.canaryTransport == nil {
		return TransportFn(func(req *http.Request) (*http.Response, error) {
			return p.tr.RoundTrip(req)
		})
	}

	return TransportFn(func(req *http.Request) (*http.Response, error) {
		if p.shouldRouteToCanary(req) {
			// Rewrite URL to canary target
			originalURL := req.URL
			req.URL = &url.URL{
				Scheme:   p.canaryTargetURL.Scheme,
				Host:     p.canaryTargetURL.Host,
				Path:     originalURL.Path,
				RawQuery: originalURL.RawQuery,
			}
			req.Host = p.canaryTargetURL.Host
			req.Header.Set("Host", p.canaryTargetURL.Host)
			req.Header.Set("X-Canary", "true")
			slog.Debug("canary: routing to canary target",
				"target", p.canaryTargetURL.String(),
				"percentage", p.Canary.Percentage)
			return p.canaryTransport.RoundTrip(req)
		}
		return p.tr.RoundTrip(req)
	})
}

// shouldRouteToCanary determines whether a request should be sent to the canary target.
// If StickyHeader is set, routing is deterministic based on a hash of the header value.
// Otherwise, routing is probabilistic based on the configured percentage.
func (p *Proxy) shouldRouteToCanary(req *http.Request) bool {
	pct := p.Canary.Percentage
	if pct <= 0 {
		return false
	}
	if pct >= 100 {
		return true
	}

	// Deterministic routing via sticky header
	if p.Canary.StickyHeader != "" {
		headerVal := req.Header.Get(p.Canary.StickyHeader)
		if headerVal != "" {
			h := fnv.New32a()
			h.Write([]byte(headerVal))
			return int(h.Sum32()%100) < pct
		}
	}

	// Probabilistic routing
	return rand.IntN(100) < pct
}

// ShadowTransport returns the shadow transport if configured
func (p *Proxy) ShadowTransport() *transportpkg.ShadowTransport {
	return p.shadowTransport
}

// RefreshTransport performs the refresh transport operation on the Proxy.
func (p *Proxy) RefreshTransport() {
	p.tr = ClientConnectionTransportFn(&p.BaseConnection, p.URL)
}

// LoadProxy performs the load proxy operation.
func LoadProxy(data []byte) (ActionConfig, error) {
	proxy := new(Proxy)
	if err := json.Unmarshal(data, proxy); err != nil {
		return nil, err
	}
	var err error
	proxy.targetURL, err = url.Parse(proxy.URL)
	if err != nil {
		return nil, ErrProxyInvalidURL
	}

	// Validate that the URL has a scheme and host
	if proxy.targetURL.Scheme == "" || proxy.targetURL.Host == "" {
		return nil, ErrProxyInvalidURL
	}

	proxy.tr = ClientConnectionTransportFn(&proxy.BaseConnection, proxy.URL)

	// Wire canary transport if configured
	if proxy.Canary != nil && proxy.Canary.Enabled && proxy.Canary.Target != "" {
		canaryURL, err := url.Parse(proxy.Canary.Target)
		if err == nil && canaryURL.Scheme != "" && canaryURL.Host != "" {
			proxy.canaryTargetURL = canaryURL
			proxy.canaryTransport = ClientConnectionTransportFn(&proxy.BaseConnection, proxy.Canary.Target)
			slog.Info("canary transport initialized",
				"target", proxy.Canary.Target,
				"percentage", proxy.Canary.Percentage,
				"sticky_header", proxy.Canary.StickyHeader)
		} else {
			slog.Warn("canary target URL invalid, disabling canary", "target", proxy.Canary.Target)
		}
	}

	// Wire shadow transport if configured
	if proxy.Shadow != nil && proxy.Shadow.UpstreamURL != "" {
		maxBodySize := int64(1 * 1024 * 1024) // 1MB default
		if proxy.Shadow.MaxBodySize != "" {
			if parsed, err := parseBodySize(proxy.Shadow.MaxBodySize); err == nil {
				maxBodySize = parsed
			}
		}

		// Percentage (1-100) takes precedence over SampleRate (0.0-1.0) if set
		sampleRate := proxy.Shadow.SampleRate
		if proxy.Shadow.Percentage > 0 && proxy.Shadow.Percentage <= 100 {
			sampleRate = float64(proxy.Shadow.Percentage) / 100.0
		}

		shadowCfg := transportpkg.ShadowConfig{
			UpstreamURL:   proxy.Shadow.UpstreamURL,
			SampleRate:    sampleRate,
			IgnoreErrors:  !proxy.Shadow.FailOnError,
			HeadersOnly:   proxy.Shadow.HeadersOnly,
			Timeout:       proxy.Shadow.Timeout.Duration,
			MaxConcurrent: proxy.Shadow.MaxConcurrent,
			MaxBodySize:   maxBodySize,
			Modifiers:     convertShadowModifiers(proxy.Shadow.Modifiers),
		}
		if proxy.Shadow.CircuitBreaker != nil {
			shadowCfg.CBFailureThreshold = proxy.Shadow.CircuitBreaker.FailureThreshold
			shadowCfg.CBSuccessThreshold = proxy.Shadow.CircuitBreaker.SuccessThreshold
			shadowCfg.CBTimeout = proxy.Shadow.CircuitBreaker.Timeout.Duration
		}
		if st, err := transportpkg.NewShadowTransport(shadowCfg); err == nil {
			proxy.shadowTransport = st
		} else {
			slog.Warn("shadow transport init failed, disabling", "error", err)
		}
	}

	return proxy, nil
}

// parseBodySize parses a size string like "1MB", "100KB", etc.
func parseBodySize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	s = strings.ToUpper(s)

	multipliers := map[string]int64{
		"B":  1,
		"KB": 1024,
		"MB": 1024 * 1024,
		"GB": 1024 * 1024 * 1024,
	}

	for suffix, mult := range multipliers {
		if strings.HasSuffix(s, suffix) {
			numStr := strings.TrimSuffix(s, suffix)
			num, err := strconv.ParseInt(numStr, 10, 64)
			if err != nil {
				return 0, err
			}
			return num * mult, nil
		}
	}

	// Try parsing as plain number (bytes)
	num, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	return num, nil
}

// convertShadowModifiers converts config shadow modifiers to transport shadow modifiers
func convertShadowModifiers(modifiers []ShadowModifier) []transportpkg.ShadowModifier {
	result := make([]transportpkg.ShadowModifier, 0, len(modifiers))
	for _, mod := range modifiers {
		if mod.Headers == nil {
			continue
		}
		result = append(result, transportpkg.ShadowModifier{
			HeadersSet:    mod.Headers.Set,
			HeadersRemove: mod.Headers.Remove,
		})
	}
	return result
}
