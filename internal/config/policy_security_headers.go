// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
)

func init() {
	policyLoaderFns[PolicyTypeSecurityHeaders] = NewSecurityHeadersPolicy
}

// SecurityHeadersPolicyConfig implements PolicyConfig for security headers
type SecurityHeadersPolicyConfig struct {
	SecurityHeadersPolicy

	// Internal
	config *Config
}

// NewSecurityHeadersPolicy creates a new security headers policy config
func NewSecurityHeadersPolicy(data []byte) (PolicyConfig, error) {
	cfg := &SecurityHeadersPolicyConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Init initializes the policy config
func (p *SecurityHeadersPolicyConfig) Init(config *Config) error {
	p.config = config
	return nil
}

// Apply implements the middleware pattern for security headers
func (p *SecurityHeadersPolicyConfig) Apply(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.Disabled {
			slog.Debug("security headers policy disabled",
				"config_id", p.config.ID,
				"path", r.URL.Path)
			next.ServeHTTP(w, r)
			return
		}

		// Log CSP configuration status
		if p.ContentSecurityPolicy != nil {
			slog.Debug("security headers policy active",
				"config_id", p.config.ID,
				"path", r.URL.Path,
				"csp_enabled", p.ContentSecurityPolicy.Enabled,
				"csp_report_only", p.ContentSecurityPolicy.ReportOnly,
				"csp_enable_nonce", p.ContentSecurityPolicy.EnableNonce,
				"csp_has_directives", p.ContentSecurityPolicy.Directives != nil,
				"csp_has_policy_string", p.ContentSecurityPolicy.Policy != "",
				"csp_has_dynamic_routes", len(p.ContentSecurityPolicy.DynamicRoutes) > 0)
		}

		// Generate CSP nonce if enabled
		var cspNonce string
		if p.ContentSecurityPolicy != nil && p.ContentSecurityPolicy.Enabled && p.ContentSecurityPolicy.EnableNonce {
			var err error
			cspNonce, err = GenerateNonce()
			if err != nil {
				slog.Warn("failed to generate CSP nonce",
					"error", err,
					"config_id", p.config.ID)
			} else {
				slog.Debug("CSP nonce generated",
					"nonce", cspNonce[:8]+"...", // Log partial nonce for debugging
					"config_id", p.config.ID,
					"path", r.URL.Path)
				// Store nonce in request context for use in templates/HTML
				r = r.WithContext(WithCSPNonce(r.Context(), cspNonce))
				// Also set as header for easy access
				w.Header().Set(CSPNonceHeader, cspNonce)
			}
		}

		// Wrap the response writer to add headers
		wrapped := &securityHeadersWriter{
			ResponseWriter: w,
			policy:         p,
			request:        r,
			cspNonce:       cspNonce,
		}

		next.ServeHTTP(wrapped, r)
	})
}

// securityHeadersWriter wraps http.ResponseWriter to add security headers
type securityHeadersWriter struct {
	http.ResponseWriter
	policy      *SecurityHeadersPolicyConfig
	request     *http.Request
	wroteHeader bool
	cspNonce    string
}

// Header returns the header map that will be sent by the WriteHeader method
func (w *securityHeadersWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}

// Hijack implements http.Hijacker to support WebSocket upgrades
func (w *securityHeadersWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
}

// WriteHeader performs the write header operation on the securityHeadersWriter.
func (w *securityHeadersWriter) WriteHeader(statusCode int) {
	if !w.wroteHeader {
		// Apply security headers only if they don't already exist from upstream
		// This check happens here because ReverseProxy copies headers before calling WriteHeader
		w.applySecurityHeaders()
		// Deduplicate security headers to handle cases where ReverseProxy or upstream
		// added duplicates using Add() instead of Set()
		w.deduplicateSecurityHeaders()
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

// Write performs the write operation on the securityHeadersWriter.
func (w *securityHeadersWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.applySecurityHeaders()
		// Deduplicate security headers to handle cases where ReverseProxy or upstream
		// added duplicates using Add() instead of Set()
		w.deduplicateSecurityHeaders()
		w.wroteHeader = true
	}
	return w.ResponseWriter.Write(b)
}

func (w *securityHeadersWriter) applySecurityHeaders() {
	p := w.policy
	h := w.ResponseWriter.Header()

	// Apply all configured security headers
	// Each method checks if the header already exists using http.Header methods
	// and respects upstream headers
	if p.StrictTransportSecurity != nil && p.StrictTransportSecurity.Enabled {
		p.applyHSTSToHeader(h)
	}

	if p.ContentSecurityPolicy != nil && p.ContentSecurityPolicy.Enabled {
		p.applyCSPToHeaderWithRequest(h, w.request, w.cspNonce)
	}

	if p.XFrameOptions != nil && p.XFrameOptions.Enabled {
		p.applyXFrameOptionsToHeader(h)
	}

	if p.XContentTypeOptions != nil && p.XContentTypeOptions.Enabled {
		p.applyXContentTypeOptionsToHeader(h)
	}

	if p.XXSSProtection != nil && p.XXSSProtection.Enabled {
		p.applyXXSSProtectionToHeader(h)
	}

	if p.ReferrerPolicy != nil && p.ReferrerPolicy.Enabled {
		p.applyReferrerPolicyToHeader(h)
	}

	if p.PermissionsPolicy != nil && p.PermissionsPolicy.Enabled {
		p.applyPermissionsPolicyToHeader(h)
	}

	if p.CrossOriginEmbedderPolicy != nil && p.CrossOriginEmbedderPolicy.Enabled {
		p.applyCOEPToHeader(h)
	}

	if p.CrossOriginOpenerPolicy != nil && p.CrossOriginOpenerPolicy.Enabled {
		p.applyCOOPToHeader(h)
	}

	if p.CrossOriginResourcePolicy != nil && p.CrossOriginResourcePolicy.Enabled {
		p.applyCORPToHeader(h)
	}
}

// deduplicateSecurityHeaders removes duplicate security headers, keeping only the first value
// This handles cases where ReverseProxy or upstream responses added duplicates using Add()
func (w *securityHeadersWriter) deduplicateSecurityHeaders() {
	h := w.ResponseWriter.Header()

	// Map of canonical header names to check
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

	// Iterate over all headers and deduplicate security headers
	// We need to check all header keys because they might be in different cases
	for key, values := range h {
		canonicalKey := http.CanonicalHeaderKey(key)
		if securityHeaderMap[canonicalKey] {
			if len(values) > 1 {
				// Keep only the first value and remove duplicates
				// Delete the original key first (in case it's different from canonical)
				delete(h, key)
				h[canonicalKey] = []string{values[0]}
			} else if key != canonicalKey {
				// If the key is not in canonical form, normalize it
				delete(h, key)
				h[canonicalKey] = values
			}
		}
	}

	// Special handling for CSP: if both regular and report-only exist, prefer report-only
	if h.Get("Content-Security-Policy-Report-Only") != "" && h.Get("Content-Security-Policy") != "" {
		h.Del("Content-Security-Policy")
	}
}

func (p *SecurityHeadersPolicyConfig) applyHSTSToHeader(h http.Header) {
	hsts := p.StrictTransportSecurity
	if hsts.MaxAge <= 0 {
		return
	}

	// Check if header already exists using http.Header.Get() for proper canonicalization
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


// applyCSPToHeader is kept for backward compatibility but is not used directly.
// Use applyCSPToHeaderWithRequest instead.
// This function is intentionally left empty to satisfy interface requirements.
//
//nolint:unused // Kept for backward compatibility
func (p *SecurityHeadersPolicyConfig) applyCSPToHeader(h http.Header) {
	_ = h // Suppress unused parameter warning
}

func (p *SecurityHeadersPolicyConfig) applyCSPToHeaderWithRequest(h http.Header, r *http.Request, nonce string) {
	csp := p.ContentSecurityPolicy
	if csp == nil || !csp.Enabled {
		return
	}

	// Get route-specific CSP if available
	routeCSP := csp.GetCSPForRoute(r.URL.Path)
	isRouteSpecific := routeCSP != csp

	if isRouteSpecific {
		slog.Debug("using route-specific CSP",
			"path", r.URL.Path,
			"config_id", p.config.ID)
	}

	// Build policy string (supports both simple string and structured directives)
	policy := routeCSP.BuildPolicyString(r, nonce, nil) // hashes would be passed if needed

	if policy == "" {
		slog.Debug("CSP policy is empty, skipping",
			"path", r.URL.Path,
			"config_id", p.config.ID)
		return
	}

	headerName := "Content-Security-Policy"
	if routeCSP.ReportOnly {
		headerName = "Content-Security-Policy-Report-Only"
		slog.Debug("CSP report-only mode enabled",
			"path", r.URL.Path,
			"config_id", p.config.ID)
	}

	// Check if CSP header already exists using http.Header.Get() for proper canonicalization
	// Check both regular and report-only variants
	if h.Get("Content-Security-Policy") != "" || h.Get("Content-Security-Policy-Report-Only") != "" {
		return
	}

	headerValue := policy
	if routeCSP.ReportURI != "" {
		// Use report-uri for older browsers, report-to for newer ones
		headerValue += "; report-uri " + routeCSP.ReportURI
	}

	h.Set(headerName, headerValue)
}


func (p *SecurityHeadersPolicyConfig) applyXFrameOptionsToHeader(h http.Header) {
	xfo := p.XFrameOptions
	if xfo.Value == "" {
		return
	}

	// Check if header already exists using http.Header.Get() for proper canonicalization
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


func (p *SecurityHeadersPolicyConfig) applyXContentTypeOptionsToHeader(h http.Header) {
	// Check if header already exists using http.Header.Get() for proper canonicalization
	if h.Get("X-Content-Type-Options") != "" {
		return
	}

	// "nosniff" is the only valid value for X-Content-Type-Options,
	// so enabled: true is sufficient (NoSniff field is kept for backward compat)
	h.Set("X-Content-Type-Options", "nosniff")
}


func (p *SecurityHeadersPolicyConfig) applyXXSSProtectionToHeader(h http.Header) {
	xxss := p.XXSSProtection
	if xxss.Mode == "" {
		return
	}

	// Check if header already exists using http.Header.Get() for proper canonicalization
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


func (p *SecurityHeadersPolicyConfig) applyReferrerPolicyToHeader(h http.Header) {
	rp := p.ReferrerPolicy
	if rp.Policy == "" {
		return
	}

	// Check if header already exists using http.Header.Get() for proper canonicalization
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


func (p *SecurityHeadersPolicyConfig) applyPermissionsPolicyToHeader(h http.Header) {
	pp := p.PermissionsPolicy
	if len(pp.Features) == 0 {
		return
	}

	// Check if header already exists using http.Header.Get() for proper canonicalization
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


func (p *SecurityHeadersPolicyConfig) applyCOEPToHeader(h http.Header) {
	coep := p.CrossOriginEmbedderPolicy
	if coep.Value == "" {
		return
	}

	// Check if header already exists using http.Header.Get() for proper canonicalization
	if h.Get("Cross-Origin-Embedder-Policy") != "" {
		return
	}

	validPolicies := []string{"unsafe-none", "require-corp"}
	if !slices.Contains(validPolicies, coep.Value) {
		return
	}

	h.Set("Cross-Origin-Embedder-Policy", coep.Value)
}


func (p *SecurityHeadersPolicyConfig) applyCOOPToHeader(h http.Header) {
	coop := p.CrossOriginOpenerPolicy
	if coop.Value == "" {
		return
	}

	// Check if header already exists using http.Header.Get() for proper canonicalization
	if h.Get("Cross-Origin-Opener-Policy") != "" {
		return
	}

	validPolicies := []string{"unsafe-none", "same-origin-allow-popups", "same-origin"}
	if !slices.Contains(validPolicies, coop.Value) {
		return
	}

	h.Set("Cross-Origin-Opener-Policy", coop.Value)
}


func (p *SecurityHeadersPolicyConfig) applyCORPToHeader(h http.Header) {
	corp := p.CrossOriginResourcePolicy
	if corp.Value == "" {
		return
	}

	// Check if header already exists using http.Header.Get() for proper canonicalization
	if h.Get("Cross-Origin-Resource-Policy") != "" {
		return
	}

	validPolicies := []string{"same-site", "same-origin", "cross-origin"}
	if !slices.Contains(validPolicies, corp.Value) {
		return
	}

	h.Set("Cross-Origin-Resource-Policy", corp.Value)
}


