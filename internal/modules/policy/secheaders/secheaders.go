// Package secheaders registers the security_headers policy.
//
// The policy has two configuration shapes that compose:
//
//   - `headers: [{name, value}]` - a list of static response headers to set.
//   - `content_security_policy:` - an optional detailed CSP block that supports
//     per-request nonce generation and per-URL-prefix policy overrides.
//
// When both are set and the CSP block has `enable_nonce` or `dynamic_routes`,
// the CSP block takes precedence over any Content-Security-Policy entry in the
// headers list. The headers list handles simple per-response injection; the
// CSP block handles CSP features that cannot be expressed as a fixed string.
package secheaders

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterPolicy("security_headers", New)
}

// SecurityHeader is a single response header name/value pair.
type SecurityHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ContentSecurityPolicy is the detailed CSP configuration block.
//
// It supports a plain policy string (identical to setting a
// Content-Security-Policy entry in `headers:`), plus two features that cannot
// be expressed as a static string:
//
//   - `enable_nonce`: a per-request nonce is generated and injected into
//     `script-src` and `style-src` directives of the resolved policy.
//   - `dynamic_routes`: a map of URL path prefixes to alternate policies.
//     Longest matching prefix wins.
type ContentSecurityPolicy struct {
	// Policy is the CSP header value (e.g. "default-src 'self'").
	Policy string `json:"policy,omitempty"`
	// EnableNonce generates a per-request nonce and injects it into the policy.
	EnableNonce bool `json:"enable_nonce,omitempty"`
	// ReportOnly emits `Content-Security-Policy-Report-Only` instead of
	// `Content-Security-Policy`.
	ReportOnly bool `json:"report_only,omitempty"`
	// ReportURI is appended to the policy as `; report-uri <uri>`.
	ReportURI string `json:"report_uri,omitempty"`
	// DynamicRoutes maps URL path prefixes to alternate CSPs.
	DynamicRoutes map[string]*ContentSecurityPolicy `json:"dynamic_routes,omitempty"`
}

// UnmarshalJSON accepts either a plain policy string or a detailed object.
// The string form is equivalent to `{"policy": "<s>"}`.
func (c *ContentSecurityPolicy) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if len(trimmed) > 0 && trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		c.Policy = s
		return nil
	}
	type alias ContentSecurityPolicy
	var tmp alias
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}
	*c = ContentSecurityPolicy(tmp)
	return nil
}

// resolveForPath returns the CSP config that applies to path. An exact key
// match wins; otherwise the longest-matching path prefix wins; otherwise
// falls back to c itself.
func (c *ContentSecurityPolicy) resolveForPath(path string) *ContentSecurityPolicy {
	if len(c.DynamicRoutes) == 0 {
		return c
	}
	if match, ok := c.DynamicRoutes[path]; ok && match != nil {
		return match
	}
	var best *ContentSecurityPolicy
	bestLen := 0
	for route, route_csp := range c.DynamicRoutes {
		if route_csp == nil {
			continue
		}
		if strings.HasPrefix(path, route) && len(route) > bestLen {
			best = route_csp
			bestLen = len(route)
		}
	}
	if best != nil {
		return best
	}
	return c
}

// requiresPerRequest reports whether this CSP needs request-time processing
// (nonce generation or dynamic-route resolution). A simple Policy string
// with no nonce/routes can be emitted via the headers list and doesn't
// require per-request work.
func (c *ContentSecurityPolicy) requiresPerRequest() bool {
	return c != nil && (c.EnableNonce || len(c.DynamicRoutes) > 0)
}

// Config is the security_headers policy configuration.
type Config struct {
	Type     string `json:"type"`
	Disabled bool   `json:"disabled,omitempty"`

	// Headers is the canonical list of response headers to inject.
	Headers []SecurityHeader `json:"headers,omitempty"`

	// ContentSecurityPolicy is an optional detailed CSP block. When set with
	// EnableNonce or DynamicRoutes, it takes precedence over any
	// Content-Security-Policy entry in Headers.
	ContentSecurityPolicy *ContentSecurityPolicy `json:"content_security_policy,omitempty"`
}

// New creates a new security_headers policy enforcer.
func New(data json.RawMessage) (plugin.PolicyEnforcer, error) {
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return &secHeadersPolicy{cfg: cfg}, nil
}

type secHeadersPolicy struct {
	cfg      *Config
	originID string
}

func (p *secHeadersPolicy) Type() string { return "security_headers" }

// CSPReportURI implements plugin.CSPReportURIProvider. It returns the CSP
// violation report URI if the detailed CSP block configures one.
func (p *secHeadersPolicy) CSPReportURI() string {
	if p.cfg.ContentSecurityPolicy != nil && p.cfg.ContentSecurityPolicy.ReportURI != "" {
		return p.cfg.ContentSecurityPolicy.ReportURI
	}
	return ""
}

// InitPlugin implements plugin.Initable to receive origin context.
func (p *secHeadersPolicy) InitPlugin(ctx plugin.PluginContext) error {
	p.originID = ctx.OriginID
	return nil
}

func (p *secHeadersPolicy) Enforce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.cfg.Disabled {
			next.ServeHTTP(w, r)
			return
		}

		var cspNonce string
		if p.cfg.ContentSecurityPolicy != nil {
			resolved := p.cfg.ContentSecurityPolicy.resolveForPath(r.URL.Path)
			if resolved.EnableNonce {
				if n, err := generateNonce(); err == nil {
					cspNonce = n
					r = r.WithContext(withCSPNonce(r.Context(), cspNonce))
					w.Header().Set(cspNonceHeader, cspNonce)
				} else {
					slog.Warn("failed to generate CSP nonce",
						"error", err,
						"config_id", p.originID)
				}
			}
		}

		wrapped := &securityHeadersWriter{
			ResponseWriter: w,
			policy:         p,
			request:        r,
			cspNonce:       cspNonce,
		}

		next.ServeHTTP(wrapped, r)
	})
}

type securityHeadersWriter struct {
	http.ResponseWriter
	policy      *secHeadersPolicy
	request     *http.Request
	wroteHeader bool
	cspNonce    string
}

func (w *securityHeadersWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}

func (w *securityHeadersWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
}

func (w *securityHeadersWriter) WriteHeader(statusCode int) {
	if !w.wroteHeader {
		w.applySecurityHeaders()
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *securityHeadersWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.applySecurityHeaders()
		w.wroteHeader = true
	}
	return w.ResponseWriter.Write(b)
}

func (w *securityHeadersWriter) applySecurityHeaders() {
	cfg := w.policy.cfg
	h := w.ResponseWriter.Header()

	// When the detailed CSP block needs per-request processing, it owns the
	// Content-Security-Policy header. We skip any CSP entry from the static
	// headers list in that case to avoid conflicts.
	cspOwnsHeader := cfg.ContentSecurityPolicy.requiresPerRequest()

	for _, hdr := range cfg.Headers {
		if cspOwnsHeader && isCSPHeader(hdr.Name) {
			continue
		}
		name := http.CanonicalHeaderKey(hdr.Name)
		if h.Get(name) != "" {
			continue
		}
		h.Set(name, hdr.Value)
	}

	if cfg.ContentSecurityPolicy != nil && cfg.ContentSecurityPolicy.Policy != "" {
		w.applyCSPBlock(h)
	}
}

func (w *securityHeadersWriter) applyCSPBlock(h http.Header) {
	csp := w.policy.cfg.ContentSecurityPolicy.resolveForPath(w.request.URL.Path)
	if csp.Policy == "" {
		return
	}
	value := csp.Policy
	if csp.EnableNonce && w.cspNonce != "" {
		value = injectNonceIntoPolicy(value, w.cspNonce)
	}
	if csp.ReportURI != "" {
		value += "; report-uri " + csp.ReportURI
	}
	name := "Content-Security-Policy"
	if csp.ReportOnly {
		name = "Content-Security-Policy-Report-Only"
	}
	// Avoid double-set if something upstream already wrote a CSP header.
	if h.Get("Content-Security-Policy") != "" || h.Get("Content-Security-Policy-Report-Only") != "" {
		return
	}
	h.Set(name, value)
}

func isCSPHeader(name string) bool {
	canonical := http.CanonicalHeaderKey(name)
	return canonical == "Content-Security-Policy" ||
		canonical == "Content-Security-Policy-Report-Only"
}

// ---- CSP helpers ----

const cspNonceHeader = "X-CSP-Nonce"

type cspNonceContextKey struct{}

var cspNonceContextKeyVal = cspNonceContextKey{}

func generateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func withCSPNonce(ctx context.Context, nonce string) context.Context {
	return context.WithValue(ctx, cspNonceContextKeyVal, nonce)
}

// CSPNonceFromContext returns the per-request CSP nonce if one was set by the
// security_headers policy.
func CSPNonceFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(cspNonceContextKeyVal).(string); ok {
		return v
	}
	return ""
}

// injectNonceIntoPolicy appends `'nonce-<nonce>'` to `script-src` and
// `style-src` directives that don't already contain a nonce. Other directives
// are left unchanged.
func injectNonceIntoPolicy(policy, nonce string) string {
	if nonce == "" {
		return policy
	}
	parts := strings.Split(policy, ";")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if (strings.HasPrefix(trimmed, "script-src") || strings.HasPrefix(trimmed, "style-src")) &&
			!strings.Contains(trimmed, "'nonce-") {
			trimmed = trimmed + " 'nonce-" + nonce + "'"
		}
		result = append(result, trimmed)
	}
	return strings.Join(result, "; ")
}
