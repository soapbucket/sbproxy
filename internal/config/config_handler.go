// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// ServeHTTP handles HTTP requests for the Config.
func (c *Config) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check request_rules (non-must_match mode: origin loads but rejects non-matching with 404)
	// When must_match_rules is true, the configloader already handled it by returning a disabled config
	if len(c.RequestRules) > 0 && !c.MustMatchRules && !c.RequestRules.Match(r) {
		slog.Debug("request rejected by request_rules",
			"config_id", c.ID,
			"path", r.URL.Path,
			"method", r.Method)
		metric.RequestRuleRejection(c.ID)
		if !c.ServeErrorPage(w, r, http.StatusNotFound, nil) {
			ct := c.DefaultContentType
			if ct == "" {
				ct = "text/plain"
			}
			w.Header().Set("Content-Type", ct)
			w.WriteHeader(http.StatusNotFound)
		}
		return
	}

	// Handle OPTIONS requests (CORS preflight)
	if r.Method == http.MethodOptions {
		// Set Allow header based on AllowedMethods if configured, otherwise use common methods
		if len(c.AllowedMethods) > 0 {
			w.Header().Set("Allow", strings.Join(c.AllowedMethods, ", "))
		} else {
			// Default to common HTTP methods if not specified
			w.Header().Set("Allow", "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS")
		}

		// Return 204 No Content for OPTIONS requests
		// Response modifiers can add CORS headers if configured
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Validate HTTP method if AllowedMethods is configured
	if len(c.AllowedMethods) > 0 {
		if err := httputil.ValidateRequestMethod(r.Method, c.AllowedMethods); err != nil {
			slog.Debug("HTTP method not allowed",
				"method", r.Method,
				"allowed_methods", c.AllowedMethods,
				"config_id", c.ID)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	}

	// Execute OnRequest callbacks if configured
	if len(c.OnRequest) > 0 {
		ctx := r.Context()
		requestData := reqctx.GetRequestData(ctx)

		// Prepare callback data using the 9-namespace model
		callbackData := make(map[string]any)

		// Populate namespace context objects
		if requestData.OriginCtx != nil {
			callbackData["origin"] = requestData.OriginCtx
		}
		if requestData.ServerCtx != nil {
			callbackData["server"] = requestData.ServerCtx
		}
		if requestData.VarsCtx != nil && requestData.VarsCtx.Data != nil {
			callbackData["vars"] = requestData.VarsCtx.Data
		}
		if requestData.FeaturesCtx != nil && requestData.FeaturesCtx.Data != nil {
			callbackData["features"] = requestData.FeaturesCtx.Data
		}
		if requestData.ClientCtx != nil {
			callbackData["client"] = requestData.ClientCtx
		}
		if requestData.SessionCtx != nil {
			callbackData["session"] = requestData.SessionCtx
		}
		if requestData.Snapshot != nil {
			callbackData["request"] = requestData.Snapshot
		}
		if requestData.CtxObj != nil {
			callbackData["ctx"] = requestData.CtxObj
		}

		// Execute callbacks sequentially with type-based naming (respects async flag for each callback)
		result, err := c.OnRequest.DoSequentialWithType(ctx, callbackData, "on_request")
		if err != nil {
			slog.Error("on_request callback failed",
				"config_id", c.ID,
				"error", err)
			// Don't fail the request if callback fails - just log the error
			// Async callbacks won't affect the request anyway
		} else if len(result) > 0 {
			// Store non-async callback results in RequestData.Data
			for k, v := range result {
				requestData.SetData(k, v)
			}
			// Update context with modified RequestData
			*r = *r.WithContext(reqctx.SetRequestData(ctx, requestData))

			slog.Debug("on_request callbacks executed",
				"config_id", c.ID,
				"result_count", len(result))
		}
	}

	// Track API version usage
	trackAPIVersion(c.ID, r)

	// Track request path distribution
	trackRequestPath(c.ID, r)

	// Track configuration feature flags
	trackConfigFeatureFlags(c)

	c.compiledRequestHandler().ServeHTTP(w, r)
}

func (c *Config) compiledRequestHandler() http.Handler {
	c.compiledHandlerOnce.Do(func() {
		c.compiledHandler = c.buildCompiledRequestHandler()
	})
	if c.compiledHandler == nil {
		return http.NotFoundHandler()
	}
	return c.compiledHandler
}

func (c *Config) buildCompiledRequestHandler() http.Handler {
	var next http.Handler

	if c.IsProxy() {
		streamingHandler := NewStreamingProxyHandler(c)
		next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slog.Debug("serve http with streaming proxy", "config", c)
			streamingHandler.ServeHTTP(w, r)
		})
	} else {
		actionHandler := c.Handler()
		next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isWebSocketUpgradeRequest(r) {
				actionHandler.ServeHTTP(w, r)
				return
			}

			errorPageWriter := &errorPageResponseWriter{
				ResponseWriter: w,
				config:         c,
				request:        r,
				startTime:      requestStartTime(r),
			}
			actionHandler.ServeHTTP(errorPageWriter, r)
		})
	}

	// Wrap with authentication middleware
	// Check both child auth and parent auth (parent propagates when DisableApplyParent is false)
	if c.auth != nil || (c.Parent != nil && !c.DisableApplyParent) {
		next = c.Authenticate(next)
	}

	if c.APIConfig != nil {
		next = APIHandler(c)(next)
	}

	// Wrap with API versioning middleware if configured.
	if c.APIVersioning != nil {
		ve := NewVersionExtractor(c.APIVersioning)
		next = ve.Middleware(next)
	}

	// Handle CSP violation reports if configured
	next = CSPReportHandler(c)(next)

	// Wrap with policy middlewares
	// Note: We iterate backwards through the array to build the middleware chain correctly,
	// but policies execute in logical order: first policy in array executes first (outermost),
	// last policy executes last (innermost, just before action handler).
	// Example: policies: [waf, rate_limit, ip_filter] executes as: waf -> rate_limit -> ip_filter -> action
	for i := len(c.policies) - 1; i >= 0; i-- {
		policy := c.policies[i]
		slog.Debug("applying policy", "policy_type", policy.GetType())
		next = policy.Apply(next)
	}

	// Apply parent policies as outermost layer (execute before child policies)
	if c.Parent != nil && !c.DisableApplyParent {
		for i := len(c.Parent.policies) - 1; i >= 0; i-- {
			policy := c.Parent.policies[i]
			slog.Debug("applying parent policy", "policy_type", policy.GetType(), "parent_id", c.Parent.ID)
			next = policy.Apply(next)
		}
	}

	if c.ForceSSL {
		next = ForceSSLMiddleware(next)
	}

	return next
}

func isWebSocketUpgradeRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func requestStartTime(r *http.Request) time.Time {
	if r != nil {
		if rd := reqctx.GetRequestData(r.Context()); rd != nil && !rd.StartTime.IsZero() {
			return rd.StartTime
		}
	}
	return time.Now()
}

// errorPageResponseWriter wraps http.ResponseWriter to intercept error status codes
type errorPageResponseWriter struct {
	http.ResponseWriter
	config           *Config
	request          *http.Request
	status           int
	written          bool
	errorPageServed  bool
	startTime        time.Time
	latencyRecorded  bool
	responseBodySize int64
	bodySizeRecorded bool
}

// Hijack implements http.Hijacker to support WebSocket upgrades
func (w *errorPageResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
}

// Flush implements http.Flusher to support streaming responses and chunk caching
func (w *errorPageResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// WriteHeader performs the write header operation on the errorPageResponseWriter.
func (w *errorPageResponseWriter) WriteHeader(status int) {
	if w.written {
		return
	}

	w.status = status
	w.written = true

	// Check for context cancellation
	if w.request.Context().Err() != nil {
		origin := w.config.ID
		if origin == "" {
			origin = "unknown"
		}
		cancelReason := "context_cancelled"
		if w.request.Context().Err() == context.DeadlineExceeded {
			cancelReason = "timeout"
		} else if w.request.Context().Err() == context.Canceled {
			cancelReason = "client_cancelled"
		}
		metric.RequestCancellation(origin, cancelReason)
		// Don't serve error page if cancelled
		return
	}

	// Record response header size
	origin := w.config.ID
	if origin == "" {
		origin = "unknown"
	}
	responseHeaderSize := int64(0)
	for name, values := range w.Header() {
		responseHeaderSize += int64(len(name))
		for _, value := range values {
			responseHeaderSize += int64(len(value))
		}
	}
	if responseHeaderSize > 0 {
		metric.ResponseHeaderSize(origin, responseHeaderSize)
	}

	// Check if this is an error status code (4xx or 5xx)
	if status >= 400 && status < 600 {
		// Try to serve custom error page
		if w.config.ServeErrorPage(w.ResponseWriter, w.request, status, nil) {
			w.errorPageServed = true
			// Record latency metric (body size will be 0 for error pages)
			w.recordLatency(status)
			return
		}
	}

	// Fall back to default behavior
	w.ResponseWriter.WriteHeader(status)
	// Record latency metric (body size recorded here if already written, otherwise will be recorded in Write)
	w.recordLatency(status)
}

// Write performs the write operation on the errorPageResponseWriter.
func (w *errorPageResponseWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}

	// Don't write body if we already served a custom error page
	if w.errorPageServed {
		return len(b), nil
	}

	n, err := w.ResponseWriter.Write(b)

	// Accumulate response body size
	if n > 0 {
		w.responseBodySize += int64(n)
		// If headers were already written and we haven't recorded body size yet, record it now
		// This handles the case where WriteHeader was called before Write, or Write was called first
		// and then more Write calls happen after WriteHeader
		if w.written && !w.bodySizeRecorded {
			w.bodySizeRecorded = true
			origin := w.config.ID
			if origin == "" {
				origin = "unknown"
			}
			statusCode := w.status
			if statusCode == 0 {
				statusCode = http.StatusOK
			}
			metric.ResponseBodySize(origin, statusCode, w.responseBodySize)
			// Record outbound bandwidth
			metric.BandwidthBytes(origin, "outbound", w.responseBodySize)
		}
	}

	return n, err
}

// recordLatency records the request latency metric
func (w *errorPageResponseWriter) recordLatency(statusCode int) {
	if w.latencyRecorded {
		return
	}
	w.latencyRecorded = true

	duration := time.Since(w.startTime).Seconds()
	origin := w.config.ID
	if origin == "" {
		origin = "unknown"
	}
	method := w.request.Method
	if method == "" {
		method = "UNKNOWN"
	}

	metric.RequestLatency(origin, method, statusCode, duration)

	// Record request volume
	// Get workspace_id from RequestData.Config
	workspaceID := "unknown"
	if requestData := reqctx.GetRequestData(w.request.Context()); requestData != nil && requestData.Config != nil {
		configParams := reqctx.ConfigParams(requestData.Config)
		if tid := configParams.GetWorkspaceID(); tid != "" {
			workspaceID = tid
		}
	}
	metric.RequestTotal(workspaceID, origin, method, statusCode)

	// Record HTTP version usage
	httpVersion := w.request.Proto
	if httpVersion == "" {
		httpVersion = "1.1" // Default HTTP/1.1
	} else if httpVersion == "HTTP/2.0" || httpVersion == "HTTP/2" {
		httpVersion = "2"
	} else if httpVersion == "HTTP/1.1" {
		httpVersion = "1.1"
	} else if httpVersion == "HTTP/1.0" {
		httpVersion = "1.0"
	} else if httpVersion == "HTTP/3.0" || httpVersion == "HTTP/3" {
		httpVersion = "3"
	}
	metric.HTTPVersionUsage(origin, httpVersion)

	// Record request body size if available
	if w.request.ContentLength > 0 {
		metric.RequestBodySize(origin, method, w.request.ContentLength)
		// Record inbound bandwidth
		metric.BandwidthBytes(origin, "inbound", w.request.ContentLength)
	}

	// Record response body size if it was already written before WriteHeader was called
	// (If WriteHeader is called first, body size will be recorded in Write() when first byte is written)
	if w.responseBodySize > 0 && !w.bodySizeRecorded {
		w.bodySizeRecorded = true
		metric.ResponseBodySize(origin, statusCode, w.responseBodySize)
		// Record outbound bandwidth
		metric.BandwidthBytes(origin, "outbound", w.responseBodySize)
	}

	// Record header sizes
	requestHeaderSize := int64(0)
	for name, values := range w.request.Header {
		requestHeaderSize += int64(len(name))
		for _, value := range values {
			requestHeaderSize += int64(len(value))
		}
	}
	if requestHeaderSize > 0 {
		metric.RequestHeaderSize(origin, requestHeaderSize)
	}
}

// ForceSSLMiddleware returns HTTP middleware for force ssl.
func ForceSSLMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Only redirect HTTP requests
		if r.TLS != nil {
			// Already HTTPS, continue
			next.ServeHTTP(w, r)
			return
		}

		// Build HTTPS URL
		httpsURL := &url.URL{
			Scheme:   "https",
			Host:     r.Host,
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
			Fragment: r.URL.Fragment,
		}

		slog.Debug("redirecting HTTP to HTTPS", "from", r.URL.String(), "to", httpsURL.String())

		// Perform redirect (301 Moved Permanently)
		http.Redirect(w, r, httpsURL.String(), http.StatusMovedPermanently)

	})
}

// trackAPIVersion extracts and records API version from request
func trackAPIVersion(origin string, r *http.Request) {
	if origin == "" {
		origin = "unknown"
	}

	apiVersion := "unknown"

	// Check Accept header for version (e.g., application/vnd.api+json;version=1)
	if accept := r.Header.Get("Accept"); accept != "" {
		if strings.Contains(accept, "version=") {
			parts := strings.Split(accept, "version=")
			if len(parts) > 1 {
				versionPart := strings.Split(parts[1], ";")[0]
				versionPart = strings.Split(versionPart, ",")[0]
				apiVersion = strings.TrimSpace(versionPart)
			}
		}
	}

	// Check X-API-Version header
	if apiVersion == "unknown" {
		if v := r.Header.Get("X-API-Version"); v != "" {
			apiVersion = v
		}
	}

	// Check path-based version (e.g., /api/v1/...)
	if apiVersion == "unknown" {
		matches := apiVersionPathPattern.FindStringSubmatch(r.URL.Path)
		if len(matches) > 1 {
			apiVersion = "v" + matches[1]
		}
	}

	// Check query parameter
	if apiVersion == "unknown" {
		if v := r.URL.Query().Get("version"); v != "" {
			apiVersion = v
		} else if v := r.URL.Query().Get("api_version"); v != "" {
			apiVersion = v
		}
	}

	metric.APIVersionUsage(origin, apiVersion)
}

// trackRequestPath records request path distribution with normalized patterns
func trackRequestPath(origin string, r *http.Request) {
	if origin == "" {
		origin = "unknown"
	}

	path := r.URL.Path
	if path == "" {
		path = "/"
	}

	// Normalize path to reduce cardinality
	// Replace UUIDs, numeric IDs, and common patterns with placeholders
	normalized := normalizePath(path)

	metric.RequestPathDistribution(origin, normalized)
}

// Pre-compiled patterns for normalizePath (avoids re-compiling per request)
var (
	apiVersionPathPattern = regexp.MustCompile(`/v(\d+(?:\.\d+)?)/`)
)

// normalizePath normalizes a path by replacing dynamic segments with placeholders.
// Uses a single-pass byte scanner instead of regex for better performance.
func normalizePath(path string) string {
	if len(path) > 200 {
		path = path[:200] + "..."
	}

	// Fast check: if no digits in path, nothing to normalize
	hasDigit := false
	for i := 0; i < len(path); i++ {
		if path[i] >= '0' && path[i] <= '9' {
			hasDigit = true
			break
		}
	}
	if !hasDigit {
		return path
	}

	// Process segments between '/' delimiters
	var b strings.Builder
	b.Grow(len(path))

	i := 0
	for i < len(path) {
		// Copy leading slashes
		if path[i] == '/' {
			b.WriteByte('/')
			i++
			continue
		}

		// Find segment end
		j := i
		for j < len(path) && path[j] != '/' {
			j++
		}
		seg := path[i:j]

		// Check UUID: exactly 36 chars, pattern 8-4-4-4-12
		if len(seg) == 36 && isUUID(seg) {
			b.WriteString("{uuid}")
		} else if isAllDigits(seg) {
			b.WriteString("{id}")
		} else if len(seg) >= 32 && isLowerHex(seg) {
			b.WriteString("{hash}")
		} else {
			b.WriteString(seg)
		}

		i = j
	}

	return b.String()
}

// isUUID checks if a 36-char string matches the UUID pattern 8-4-4-4-12 with lowercase hex.
func isUUID(s string) bool {
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// isAllDigits checks if a non-empty string contains only ASCII digits.
func isAllDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isLowerHex checks if a string contains only lowercase hex characters (0-9, a-f).
func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// HasSessionConfig checks if SessionConfig is present (non-empty)
// A SessionConfig is considered present if it has at least one of:
// - CookieName set
// - Callbacks defined
// - CookieMaxAge set (non-zero)
// - Any other non-default field set
func (c *Config) HasSessionConfig() bool {
	sc := c.SessionConfig
	// Check if any meaningful field is set
	return sc.CookieName != "" ||
		len(sc.OnSessionStart) > 0 ||
		sc.CookieMaxAge > 0 ||
		sc.CookieSameSite != "" ||
		sc.DisableHttpOnly ||
		sc.AllowNonSSL
}

func trackConfigFeatureFlags(c *Config) {
	// Feature flags are config-level, not request-level.
	// Use sync.Once to emit metrics only once per config instance.
	c.featureFlagsOnce.Do(func() {
		metric.FeatureFlagUsage("force_ssl", c.ForceSSL)
		metric.FeatureFlagUsage("disable_compression", c.DisableCompression)
		metric.FeatureFlagUsage("disable_http3", c.DisableHTTP3)
		metric.FeatureFlagUsage("disable_security", c.DisableSecurity)
		if c.APIConfig != nil {
			metric.FeatureFlagUsage("enable_api", c.APIConfig.EnableAPI)
		}
	})
}
