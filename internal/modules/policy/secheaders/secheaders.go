// Package secheaders registers the security_headers policy.
package secheaders

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterPolicy("security_headers", New)
}

// ---- Config types ----

// HSTSConfig holds configuration for HSTS.
type HSTSConfig struct {
	Enabled           bool `json:"enabled,omitempty"`
	MaxAge            int  `json:"max_age,omitempty"`
	IncludeSubdomains bool `json:"include_subdomains,omitempty"`
	Preload           bool `json:"preload,omitempty"`
}

// CSPDirectives holds structured CSP directives.
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

// CSPConfig holds CSP configuration.
type CSPConfig struct {
	Enabled       bool                  `json:"enabled,omitempty"`
	Policy        string                `json:"policy,omitempty"`
	ReportOnly    bool                  `json:"report_only,omitempty"`
	ReportURI     string                `json:"report_uri,omitempty"`
	Directives    *CSPDirectives        `json:"directives,omitempty"`
	EnableNonce   bool                  `json:"enable_nonce,omitempty"`
	EnableHash    bool                  `json:"enable_hash,omitempty"`
	DynamicRoutes map[string]*CSPConfig `json:"dynamic_routes,omitempty"`
}

// XFrameOptionsConfig holds X-Frame-Options configuration.
type XFrameOptionsConfig struct {
	Enabled bool   `json:"enabled,omitempty"`
	Value   string `json:"value,omitempty"`
}

// XContentTypeOptionsConfig holds X-Content-Type-Options configuration.
type XContentTypeOptionsConfig struct {
	Enabled bool `json:"enabled,omitempty"`
	NoSniff bool `json:"no_sniff,omitempty"`
}

// XXSSProtectionConfig holds X-XSS-Protection configuration.
type XXSSProtectionConfig struct {
	Enabled bool   `json:"enabled,omitempty"`
	Mode    string `json:"mode,omitempty"`
}

// ReferrerPolicyConfig holds Referrer-Policy configuration.
type ReferrerPolicyConfig struct {
	Enabled bool   `json:"enabled,omitempty"`
	Policy  string `json:"policy,omitempty"`
}

// PermissionsPolicyConfig holds Permissions-Policy configuration.
type PermissionsPolicyConfig struct {
	Enabled  bool              `json:"enabled,omitempty"`
	Features map[string]string `json:"features,omitempty"`
}

// COEPConfig holds Cross-Origin-Embedder-Policy configuration.
type COEPConfig struct {
	Enabled bool   `json:"enabled,omitempty"`
	Value   string `json:"value,omitempty"`
}

// COOPConfig holds Cross-Origin-Opener-Policy configuration.
type COOPConfig struct {
	Enabled bool   `json:"enabled,omitempty"`
	Value   string `json:"value,omitempty"`
}

// CORPConfig holds Cross-Origin-Resource-Policy configuration.
type CORPConfig struct {
	Enabled bool   `json:"enabled,omitempty"`
	Value   string `json:"value,omitempty"`
}

// Config holds configuration for the security_headers policy.
type Config struct {
	Type                      string                     `json:"type"`
	Disabled                  bool                       `json:"disabled,omitempty"`
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
// violation report URI if Content-Security-Policy reporting is enabled.
func (p *secHeadersPolicy) CSPReportURI() string {
	if p.cfg.ContentSecurityPolicy != nil &&
		p.cfg.ContentSecurityPolicy.Enabled &&
		p.cfg.ContentSecurityPolicy.ReportURI != "" {
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
			slog.Debug("security headers policy disabled",
				"config_id", p.originID,
				"path", r.URL.Path)
			next.ServeHTTP(w, r)
			return
		}

		if p.cfg.ContentSecurityPolicy != nil {
			slog.Debug("security headers policy active",
				"config_id", p.originID,
				"path", r.URL.Path,
				"csp_enabled", p.cfg.ContentSecurityPolicy.Enabled,
				"csp_report_only", p.cfg.ContentSecurityPolicy.ReportOnly,
				"csp_enable_nonce", p.cfg.ContentSecurityPolicy.EnableNonce,
				"csp_has_directives", p.cfg.ContentSecurityPolicy.Directives != nil,
				"csp_has_policy_string", p.cfg.ContentSecurityPolicy.Policy != "",
				"csp_has_dynamic_routes", len(p.cfg.ContentSecurityPolicy.DynamicRoutes) > 0)
		}

		var cspNonce string
		if p.cfg.ContentSecurityPolicy != nil && p.cfg.ContentSecurityPolicy.Enabled && p.cfg.ContentSecurityPolicy.EnableNonce {
			var err error
			cspNonce, err = generateNonce()
			if err != nil {
				slog.Warn("failed to generate CSP nonce",
					"error", err,
					"config_id", p.originID)
			} else {
				slog.Debug("CSP nonce generated",
					"nonce", cspNonce[:8]+"...",
					"config_id", p.originID,
					"path", r.URL.Path)
				r = r.WithContext(withCSPNonce(r.Context(), cspNonce))
				w.Header().Set(cspNonceHeader, cspNonce)
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
		w.deduplicateSecurityHeaders()
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *securityHeadersWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.applySecurityHeaders()
		w.deduplicateSecurityHeaders()
		w.wroteHeader = true
	}
	return w.ResponseWriter.Write(b)
}

func (w *securityHeadersWriter) applySecurityHeaders() {
	p := w.policy.cfg
	h := w.ResponseWriter.Header()

	if p.StrictTransportSecurity != nil && p.StrictTransportSecurity.Enabled {
		applyHSTS(h, p.StrictTransportSecurity)
	}
	if p.ContentSecurityPolicy != nil && p.ContentSecurityPolicy.Enabled {
		applyCSP(h, w.request, p.ContentSecurityPolicy, w.cspNonce)
	}
	if p.XFrameOptions != nil && p.XFrameOptions.Enabled {
		applyXFrameOptions(h, p.XFrameOptions)
	}
	if p.XContentTypeOptions != nil && p.XContentTypeOptions.Enabled {
		applyXContentTypeOptions(h)
	}
	if p.XXSSProtection != nil && p.XXSSProtection.Enabled {
		applyXXSSProtection(h, p.XXSSProtection)
	}
	if p.ReferrerPolicy != nil && p.ReferrerPolicy.Enabled {
		applyReferrerPolicy(h, p.ReferrerPolicy)
	}
	if p.PermissionsPolicy != nil && p.PermissionsPolicy.Enabled {
		applyPermissionsPolicy(h, p.PermissionsPolicy)
	}
	if p.CrossOriginEmbedderPolicy != nil && p.CrossOriginEmbedderPolicy.Enabled {
		applyCOEP(h, p.CrossOriginEmbedderPolicy)
	}
	if p.CrossOriginOpenerPolicy != nil && p.CrossOriginOpenerPolicy.Enabled {
		applyCOOP(h, p.CrossOriginOpenerPolicy)
	}
	if p.CrossOriginResourcePolicy != nil && p.CrossOriginResourcePolicy.Enabled {
		applyCORP(h, p.CrossOriginResourcePolicy)
	}
}

func (w *securityHeadersWriter) deduplicateSecurityHeaders() {
	h := w.ResponseWriter.Header()

	securityHeaderMap := map[string]bool{
		"Content-Security-Policy":             true,
		"Content-Security-Policy-Report-Only": true,
		"Strict-Transport-Security":           true,
		"X-Frame-Options":                     true,
		"X-Content-Type-Options":              true,
		"X-XSS-Protection":                    true,
		"Referrer-Policy":                     true,
		"Permissions-Policy":                  true,
		"Cross-Origin-Embedder-Policy":        true,
		"Cross-Origin-Opener-Policy":          true,
		"Cross-Origin-Resource-Policy":        true,
	}

	for key, values := range h {
		canonicalKey := http.CanonicalHeaderKey(key)
		if securityHeaderMap[canonicalKey] {
			if len(values) > 1 {
				delete(h, key)
				h[canonicalKey] = []string{values[0]}
			} else if key != canonicalKey {
				delete(h, key)
				h[canonicalKey] = values
			}
		}
	}

	if h.Get("Content-Security-Policy-Report-Only") != "" && h.Get("Content-Security-Policy") != "" {
		h.Del("Content-Security-Policy")
	}
}

// ---- Header application helpers ----

func applyHSTS(h http.Header, hsts *HSTSConfig) {
	if hsts.MaxAge <= 0 {
		return
	}
	if h.Get("Strict-Transport-Security") != "" {
		return
	}
	headerValue := fmt.Sprintf("max-age=%d", hsts.MaxAge)
	if hsts.IncludeSubdomains {
		headerValue += "; includeSubDomains"
	}
	if hsts.Preload {
		headerValue += "; preload"
	}
	h.Set("Strict-Transport-Security", headerValue)
}

func applyCSP(h http.Header, r *http.Request, csp *CSPConfig, nonce string) {
	if csp == nil || !csp.Enabled {
		return
	}

	routeCSP := csp.getCSPForRoute(r.URL.Path)
	policy := routeCSP.buildPolicyString(r, nonce, nil)

	if policy == "" {
		return
	}

	headerName := "Content-Security-Policy"
	if routeCSP.ReportOnly {
		headerName = "Content-Security-Policy-Report-Only"
	}

	if h.Get("Content-Security-Policy") != "" || h.Get("Content-Security-Policy-Report-Only") != "" {
		return
	}

	headerValue := policy
	if routeCSP.ReportURI != "" {
		headerValue += "; report-uri " + routeCSP.ReportURI
	}
	h.Set(headerName, headerValue)
}

func applyXFrameOptions(h http.Header, xfo *XFrameOptionsConfig) {
	if xfo.Value == "" {
		return
	}
	if h.Get("X-Frame-Options") != "" {
		return
	}
	validValues := []string{"DENY", "SAMEORIGIN", "ALLOW-FROM"}
	value := strings.ToUpper(xfo.Value)
	if !slices.Contains(validValues, value) && !strings.HasPrefix(value, "ALLOW-FROM ") {
		return
	}
	h.Set("X-Frame-Options", xfo.Value)
}

func applyXContentTypeOptions(h http.Header) {
	if h.Get("X-Content-Type-Options") != "" {
		return
	}
	h.Set("X-Content-Type-Options", "nosniff")
}

func applyXXSSProtection(h http.Header, xxss *XXSSProtectionConfig) {
	if xxss.Mode == "" {
		return
	}
	if h.Get("X-XSS-Protection") != "" {
		return
	}
	var headerValue string
	switch xxss.Mode {
	case "0":
		headerValue = "0"
	case "1":
		headerValue = "1"
	case "block":
		headerValue = "1; mode=block"
	case "report":
		headerValue = "1; report="
	default:
		return
	}
	h.Set("X-XSS-Protection", headerValue)
}

func applyReferrerPolicy(h http.Header, rp *ReferrerPolicyConfig) {
	if rp.Policy == "" {
		return
	}
	if h.Get("Referrer-Policy") != "" {
		return
	}
	validPolicies := []string{
		"no-referrer", "no-referrer-when-downgrade", "origin",
		"origin-when-cross-origin", "same-origin", "strict-origin",
		"strict-origin-when-cross-origin", "unsafe-url",
	}
	if !slices.Contains(validPolicies, rp.Policy) {
		return
	}
	h.Set("Referrer-Policy", rp.Policy)
}

func applyPermissionsPolicy(h http.Header, pp *PermissionsPolicyConfig) {
	if len(pp.Features) == 0 {
		return
	}
	if h.Get("Permissions-Policy") != "" {
		return
	}
	var policies []string
	for feature, value := range pp.Features {
		if feature == "" {
			continue
		}
		policies = append(policies, fmt.Sprintf("%s=(%s)", feature, value))
	}
	if len(policies) > 0 {
		h.Set("Permissions-Policy", strings.Join(policies, ", "))
	}
}

func applyCOEP(h http.Header, coep *COEPConfig) {
	if coep.Value == "" {
		return
	}
	if h.Get("Cross-Origin-Embedder-Policy") != "" {
		return
	}
	validPolicies := []string{"unsafe-none", "require-corp"}
	if !slices.Contains(validPolicies, coep.Value) {
		return
	}
	h.Set("Cross-Origin-Embedder-Policy", coep.Value)
}

func applyCOOP(h http.Header, coop *COOPConfig) {
	if coop.Value == "" {
		return
	}
	if h.Get("Cross-Origin-Opener-Policy") != "" {
		return
	}
	validPolicies := []string{"unsafe-none", "same-origin-allow-popups", "same-origin"}
	if !slices.Contains(validPolicies, coop.Value) {
		return
	}
	h.Set("Cross-Origin-Opener-Policy", coop.Value)
}

func applyCORP(h http.Header, corp *CORPConfig) {
	if corp.Value == "" {
		return
	}
	if h.Get("Cross-Origin-Resource-Policy") != "" {
		return
	}
	validPolicies := []string{"same-site", "same-origin", "cross-origin"}
	if !slices.Contains(validPolicies, corp.Value) {
		return
	}
	h.Set("Cross-Origin-Resource-Policy", corp.Value)
}

// ---- CSP helpers (inlined from internal/config/csp.go) ----

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

func calculateHash(content string) string {
	if content == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(content))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// keep calculateHash referenced
var _ = calculateHash

func (c *CSPConfig) getCSPForRoute(path string) *CSPConfig {
	if c.DynamicRoutes == nil {
		return c
	}
	if routeCSP, ok := c.DynamicRoutes[path]; ok {
		return routeCSP
	}
	var bestMatch *CSPConfig
	var bestMatchLen int
	for route, routeCSP := range c.DynamicRoutes {
		if strings.HasPrefix(path, route) && len(route) > bestMatchLen {
			bestMatch = routeCSP
			bestMatchLen = len(route)
		}
	}
	if bestMatch != nil {
		return bestMatch
	}
	return c
}

func (c *CSPConfig) buildPolicyString(r *http.Request, nonce string, hashes []string) string {
	routeCSP := c.getCSPForRoute(r.URL.Path)
	if routeCSP.Policy != "" {
		policy := routeCSP.Policy
		if routeCSP.EnableNonce && nonce != "" {
			policy = injectNonceIntoPolicy(policy, nonce)
		}
		return policy
	}
	if routeCSP.Directives != nil {
		return buildCSPPolicy(routeCSP.Directives, nonce, hashes)
	}
	return ""
}

func injectNonceIntoPolicy(policy, nonce string) string {
	parts := strings.Split(policy, ";")
	var result []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "script-src") || strings.HasPrefix(part, "style-src") {
			if !strings.Contains(part, "'nonce-") {
				part += " 'nonce-" + nonce + "'"
			}
		}
		result = append(result, part)
	}
	return strings.Join(result, "; ")
}

func buildCSPPolicy(directives *CSPDirectives, nonce string, hashes []string) string {
	if directives == nil {
		return ""
	}
	var parts []string

	if len(directives.DefaultSrc) > 0 {
		parts = append(parts, "default-src "+strings.Join(directives.DefaultSrc, " "))
	}
	if len(directives.ScriptSrc) > 0 {
		scriptSrc := make([]string, len(directives.ScriptSrc))
		copy(scriptSrc, directives.ScriptSrc)
		if nonce != "" {
			scriptSrc = append(scriptSrc, fmt.Sprintf("'nonce-%s'", nonce))
		}
		for _, hash := range hashes {
			scriptSrc = append(scriptSrc, fmt.Sprintf("'sha256-%s'", hash))
		}
		parts = append(parts, "script-src "+strings.Join(scriptSrc, " "))
	}
	if len(directives.StyleSrc) > 0 {
		styleSrc := make([]string, len(directives.StyleSrc))
		copy(styleSrc, directives.StyleSrc)
		if nonce != "" {
			styleSrc = append(styleSrc, fmt.Sprintf("'nonce-%s'", nonce))
		}
		for _, hash := range hashes {
			styleSrc = append(styleSrc, fmt.Sprintf("'sha256-%s'", hash))
		}
		parts = append(parts, "style-src "+strings.Join(styleSrc, " "))
	}
	if len(directives.ImgSrc) > 0 {
		parts = append(parts, "img-src "+strings.Join(directives.ImgSrc, " "))
	}
	if len(directives.FontSrc) > 0 {
		parts = append(parts, "font-src "+strings.Join(directives.FontSrc, " "))
	}
	if len(directives.ConnectSrc) > 0 {
		parts = append(parts, "connect-src "+strings.Join(directives.ConnectSrc, " "))
	}
	if len(directives.FrameSrc) > 0 {
		parts = append(parts, "frame-src "+strings.Join(directives.FrameSrc, " "))
	}
	if len(directives.ObjectSrc) > 0 {
		parts = append(parts, "object-src "+strings.Join(directives.ObjectSrc, " "))
	}
	if len(directives.MediaSrc) > 0 {
		parts = append(parts, "media-src "+strings.Join(directives.MediaSrc, " "))
	}
	if len(directives.FrameAncestors) > 0 {
		parts = append(parts, "frame-ancestors "+strings.Join(directives.FrameAncestors, " "))
	}
	if len(directives.BaseURI) > 0 {
		parts = append(parts, "base-uri "+strings.Join(directives.BaseURI, " "))
	}
	if len(directives.FormAction) > 0 {
		parts = append(parts, "form-action "+strings.Join(directives.FormAction, " "))
	}
	if directives.UpgradeInsecureRequests {
		parts = append(parts, "upgrade-insecure-requests")
	}
	return strings.Join(parts, "; ")
}
