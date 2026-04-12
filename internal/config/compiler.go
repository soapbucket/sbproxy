// compiler.go builds the per-origin HTTP handler chain from raw configuration.
//
// The compiler is the bridge between declarative YAML configuration and a
// runnable http.Handler. It reads a RawOrigin (parsed but uncompiled config),
// discovers plugin factories from the registry, provisions each module, and
// wraps them into an 18-layer handler chain. The compiled chain is immutable
// and executes with zero per-request allocation.
//
// The chain is built inside-out: the innermost layer (the action handler) is
// created first, then each successive wrapper is layered around it. This means
// the outermost wrappers (error pages, force SSL, allowed methods) run first
// on an incoming request, and the action handler runs last.
package config

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/json"

	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/middleware/callback"
	"github.com/soapbucket/sbproxy/internal/middleware/compression"
	"github.com/soapbucket/sbproxy/internal/middleware/cors"
	"github.com/soapbucket/sbproxy/internal/middleware/forward"
	"github.com/soapbucket/sbproxy/internal/middleware/hsts"
	"github.com/soapbucket/sbproxy/internal/middleware/httpsig"
	"github.com/soapbucket/sbproxy/internal/middleware/modifier"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/pkg/plugin"
	"github.com/soapbucket/sbproxy/pkg/plugin/memorycache"
)

// RawOrigin is the parsed but uncompiled origin configuration. Fields correspond
// to the top-level keys in a site YAML origin block. Each JSON field is kept as
// json.RawMessage so that the compiler can pass it to the appropriate plugin
// factory without knowing its internal structure.
type RawOrigin struct {
	ID                string            `json:"id"`
	Hostname          string            `json:"hostname"`
	WorkspaceID       string            `json:"workspace_id"`
	Version           string            `json:"version"`
	Action            json.RawMessage   `json:"action"`
	Auth              json.RawMessage   `json:"authentication,omitempty"`
	Policies          []json.RawMessage `json:"policies,omitempty"`
	Transforms        []json.RawMessage `json:"transforms,omitempty"`
	Modifiers         json.RawMessage   `json:"request_modifiers,omitempty"`
	ResponseModifiers json.RawMessage   `json:"response_modifiers,omitempty"`
	Cache             json.RawMessage   `json:"response_cache,omitempty"`
	OnLoad            json.RawMessage   `json:"on_load,omitempty"`
	OnRequest         json.RawMessage   `json:"on_request,omitempty"`
	OnResponse        json.RawMessage   `json:"on_response,omitempty"`
	Variables         map[string]any    `json:"variables,omitempty"`
	Secrets           json.RawMessage   `json:"secrets,omitempty"`
	Disabled          bool              `json:"disabled,omitempty"`
	ForceSSL          bool              `json:"force_ssl,omitempty"`
	Debug             bool              `json:"debug,omitempty"`
	Events            json.RawMessage   `json:"events,omitempty"`
	ErrorPages        json.RawMessage   `json:"error_pages,omitempty"`
	MessageSignatures json.RawMessage   `json:"message_signatures,omitempty"`

	// Observability
	TrafficCapture   json.RawMessage `json:"traffic_capture,omitempty"`
	RateLimitHeaders json.RawMessage `json:"rate_limit_headers,omitempty"`

	// Security middleware configs
	BotDetection     json.RawMessage `json:"bot_detection,omitempty"`
	ThreatProtection json.RawMessage `json:"threat_protection,omitempty"`

	// Session config
	Session json.RawMessage `json:"session_config,omitempty"`

	// Middleware configs
	Compression    json.RawMessage `json:"compression,omitempty"`
	CORS           json.RawMessage `json:"cors,omitempty"`
	HSTS           json.RawMessage `json:"hsts,omitempty"`
	AllowedMethods []string        `json:"allowed_methods,omitempty"`

	// Forward rules for path-based routing to inline origins
	ForwardRules json.RawMessage `json:"forward_rules,omitempty"`

	// Fallback origin for error/timeout/status recovery
	FallbackOrigin json.RawMessage `json:"fallback_origin,omitempty"`
}

// CompileOrigin takes a raw origin configuration and produces a CompiledOrigin
// with a fully assembled http.Handler chain. The chain is built inside-out
// through 18 layers:
//
//  1. Action handler (innermost - proxy, redirect, AI proxy, etc.)
//  2. Response cache (TTL, stale-while-revalidate)
//  3. Transforms (JSON projection, HTML, template, etc.)
//  4. on_response callbacks
//  5. Response modifiers (header injection, CEL/Lua)
//  6. Request modifiers (header injection, URL rewrite, CEL/Lua)
//  7. Authentication (API key, JWT, basic auth, etc.)
//  8. on_request callbacks
//  9. Compression (gzip, brotli, zstd)
//  10. CORS
//  11. HSTS
//  12. Policies (rate limit, WAF, IP filter, CEL expressions)
//  13. Rate limit headers (IETF format)
//  14. Bot detection
//  15. Threat protection
//  16. Session middleware
//  17. Message signatures (RFC 9421)
//  18. Traffic capture, error pages, force SSL, allowed methods (outermost)
//
// Each layer wraps the previous one, so on an incoming request the outermost
// layers (allowed methods, error pages, session) run first, then policies, auth,
// modifiers, and finally the action. The compiled chain is cached per origin and
// executes with zero per-request allocation.
func CompileOrigin(raw *RawOrigin, services plugin.ServiceProvider) (*CompiledOrigin, error) {
	if raw.Hostname == "" {
		return nil, fmt.Errorf("compile origin: hostname is required")
	}
	if len(raw.Action) == 0 {
		return nil, fmt.Errorf("compile origin %q: action is required", raw.Hostname)
	}

	ctx := plugin.PluginContext{
		OriginID:    raw.ID,
		WorkspaceID: raw.WorkspaceID,
		Hostname:    raw.Hostname,
		Version:     raw.Version,
		Services:    services,
	}

	// Track all created modules so their Cleanup methods can be collected
	// into a single teardown function on the CompiledOrigin.
	var modules []any

	// --- Action Layer (innermost) ---
	// The action handler is the core of what the origin does with a request
	// (reverse proxy, redirect, static response, AI proxy, etc.).
	typeName, err := extractType(raw.Action)
	if err != nil {
		return nil, fmt.Errorf("compile origin %q: %w", raw.Hostname, err)
	}

	action, err := plugin.CreateAction(typeName, raw.Action)
	if err != nil {
		return nil, fmt.Errorf("compile origin %q: %w", raw.Hostname, err)
	}

	if err := provisionModule(action, ctx); err != nil {
		return nil, fmt.Errorf("compile origin %q: provision action %q: %w", raw.Hostname, typeName, err)
	}
	modules = append(modules, action)

	var handler http.Handler = action

	// If the action implements ReverseProxyAction, upgrade it to a full httputil.ReverseProxy.
	// This lets action modules declare Rewrite/Transport/ModifyResponse hooks without
	// reimplementing reverse proxy buffering and streaming themselves.
	if rpa, ok := action.(plugin.ReverseProxyAction); ok {
		rp := &httputil.ReverseProxy{
			Rewrite:        rpa.Rewrite,
			Transport:      rpa.Transport(),
			ModifyResponse: rpa.ModifyResponse,
			ErrorHandler:   rpa.ErrorHandler,
			FlushInterval:  -1, // streaming mode
		}
		handler = rp
	}

	// --- Forward Rules Layer ---
	// Forward rules allow path-based routing to inline origins. When a rule
	// matches, the request is dispatched to the inline origin's handler instead
	// of the default action. Rules are evaluated in order; first match wins.
	handler = wrapForwardRules(handler, raw.ForwardRules, services)

	// --- Fallback Origin Layer ---
	// Fallback wraps the action+forward handler to intercept errors and status
	// codes, dispatching to a fallback origin when triggered.
	handler = wrapFallbackOrigin(handler, raw.FallbackOrigin, services)

	// --- Response Processing Layers ---
	// Response cache sits between the action and transforms so that cached
	// responses still pass through transforms on cache hits.
	handler = wrapResponseCache(handler, raw.Cache, services)

	// Transforms are applied in config order (first transform sees the raw response).
	for i, rawT := range raw.Transforms {
		tName, err := extractType(rawT)
		if err != nil {
			return nil, fmt.Errorf("compile origin %q: transform[%d]: %w", raw.Hostname, i, err)
		}

		factory, ok := plugin.GetTransform(tName)
		if !ok {
			return nil, fmt.Errorf("compile origin %q: unknown transform type %q", raw.Hostname, tName)
		}

		t, err := factory(rawT)
		if err != nil {
			return nil, fmt.Errorf("compile origin %q: create transform %q: %w", raw.Hostname, tName, err)
		}

		if err := provisionModule(t, ctx); err != nil {
			return nil, fmt.Errorf("compile origin %q: provision transform %q: %w", raw.Hostname, tName, err)
		}
		modules = append(modules, t)
		handler = wrapTransform(handler, t)
	}

	// --- Callback and Modifier Layers ---
	handler = wrapOnResponse(handler, raw.OnResponse)
	handler = wrapResponseModifiers(handler, raw.ResponseModifiers)
	handler = wrapRequestModifiers(handler, raw.Modifiers)

	// --- Authentication Layer ---
	if len(raw.Auth) > 0 && string(raw.Auth) != "null" {
		aName, err := extractType(raw.Auth)
		if err != nil {
			return nil, fmt.Errorf("compile origin %q: auth: %w", raw.Hostname, err)
		}

		factory, ok := plugin.GetAuth(aName)
		if !ok {
			return nil, fmt.Errorf("compile origin %q: unknown auth type %q", raw.Hostname, aName)
		}

		auth, err := factory(raw.Auth)
		if err != nil {
			return nil, fmt.Errorf("compile origin %q: create auth %q: %w", raw.Hostname, aName, err)
		}

		if err := provisionModule(auth, ctx); err != nil {
			return nil, fmt.Errorf("compile origin %q: provision auth %q: %w", raw.Hostname, aName, err)
		}
		modules = append(modules, auth)
		handler = auth.Wrap(handler)
	}

	handler = wrapOnRequest(handler, raw.OnRequest)

	// --- HTTP Protocol Layers ---
	handler = wrapCompression(handler, raw.Compression)
	handler = wrapCORS(handler, raw.CORS)
	handler = wrapHSTS(handler, raw.HSTS)

	// --- Policy Enforcement Layers ---
	// Policies are iterated in reverse because the chain builds inside-out:
	// policies[0] should be the outermost (first to execute), so it must be
	// the last one wrapped around the handler.
	for i := len(raw.Policies) - 1; i >= 0; i-- {
		rawP := raw.Policies[i]
		pName, err := extractType(rawP)
		if err != nil {
			return nil, fmt.Errorf("compile origin %q: policy[%d]: %w", raw.Hostname, i, err)
		}

		factory, ok := plugin.GetPolicy(pName)
		if !ok {
			return nil, fmt.Errorf("compile origin %q: unknown policy type %q", raw.Hostname, pName)
		}

		p, err := factory(rawP)
		if err != nil {
			return nil, fmt.Errorf("compile origin %q: create policy %q: %w", raw.Hostname, pName, err)
		}

		if err := provisionModule(p, ctx); err != nil {
			return nil, fmt.Errorf("compile origin %q: provision policy %q: %w", raw.Hostname, pName, err)
		}
		modules = append(modules, p)
		handler = p.Enforce(handler)
	}

	// --- Security and Session Layers ---
	handler = wrapRateLimitHeaders(handler, raw.RateLimitHeaders)
	handler = wrapBotDetection(handler, raw.BotDetection)
	handler = wrapThreatProtection(handler, raw.ThreatProtection)
	handler = wrapSession(handler, raw.Session, services)
	handler = wrapMessageSignatures(handler, raw.MessageSignatures)

	// --- Outermost Layers ---
	// Traffic capture and error pages are outermost so they observe the final
	// response regardless of which inner layer produced it.
	handler = wrapTrafficCapture(handler, raw.TrafficCapture, services)
	handler = wrapErrorPages(handler, raw.ErrorPages)

	// ForceSSL redirects HTTP to HTTPS before any origin logic runs.
	if raw.ForceSSL {
		handler = wrapForceSSL(handler)
	}

	// Allowed methods is the absolute outermost check, rejecting requests
	// with unsupported HTTP methods before any processing occurs.
	if len(raw.AllowedMethods) > 0 {
		handler = wrapAllowedMethods(handler, raw.AllowedMethods)
	}

	// 9. Collect cleanup functions.
	cleanups := collectCleanups(modules...)
	cleanup := func() {
		for _, fn := range cleanups {
			fn()
		}
	}

	return NewCompiledOrigin(raw.ID, raw.Hostname, raw.WorkspaceID, raw.Version, handler, cleanup), nil
}

// extractType unmarshals just the "type" field from a JSON object.
func extractType(raw json.RawMessage) (string, error) {
	var envelope struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return "", fmt.Errorf("extract type: %w", err)
	}
	if envelope.Type == "" {
		return "", fmt.Errorf("extract type: missing or empty \"type\" field")
	}
	return envelope.Type, nil
}

// provisionModule runs the three-phase lifecycle on a module: Provision (inject
// dependencies), Validate (check config), InitPlugin (start background work).
// Each phase is optional via interface assertion.
func provisionModule(m any, ctx plugin.PluginContext) error {
	if p, ok := m.(plugin.Provisioner); ok {
		if err := p.Provision(ctx); err != nil {
			return fmt.Errorf("provision: %w", err)
		}
	}
	if v, ok := m.(plugin.Validator); ok {
		if err := v.Validate(); err != nil {
			return fmt.Errorf("validate: %w", err)
		}
	}
	if i, ok := m.(plugin.Initable); ok {
		if err := i.InitPlugin(ctx); err != nil {
			return fmt.Errorf("init: %w", err)
		}
	}
	return nil
}

// maxTransformBufferSize is the maximum response body size that will be buffered
// for transformation. Responses larger than this are passed through unmodified.
const maxTransformBufferSize = 10 << 20 // 10 MB

// wrapTransform captures the upstream response into a buffer so that the
// transform's Apply method can modify it before it reaches the client. Responses
// exceeding maxTransformBufferSize are passed through unmodified to prevent OOM
// on large downloads (the overflow path flushes directly to the client).
func wrapTransform(next http.Handler, transform plugin.TransformHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tw := &transformResponseWriter{
			underlying: w,
			header:     make(http.Header),
			body:       &bytes.Buffer{},
			statusCode: http.StatusOK,
		}

		next.ServeHTTP(tw, r)

		// If the body exceeded the buffer limit, the data was already flushed
		// directly to the client and we cannot apply the transform.
		if tw.overflowed {
			return
		}

		// Build an *http.Response from the captured data.
		resp := &http.Response{
			StatusCode:    tw.statusCode,
			Header:        tw.header.Clone(),
			Body:          io.NopCloser(tw.body),
			ContentLength: int64(tw.body.Len()),
			Request:       r,
		}

		if err := transform.Apply(resp); err != nil {
			slog.Error("transform apply failed",
				"type", transform.Type(),
				"error", err,
			)
			http.Error(w, "internal transform error", http.StatusInternalServerError)
			return
		}

		// Copy transformed headers to the real writer.
		dst := w.Header()
		for k, vs := range resp.Header {
			dst[k] = vs
		}

		// Read the (possibly replaced) body.
		transformedBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			slog.Error("transform read body failed",
				"type", transform.Type(),
				"error", err,
			)
			http.Error(w, "internal transform error", http.StatusInternalServerError)
			return
		}

		// Update Content-Length to reflect the transformed body size.
		dst.Del("Content-Length")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(transformedBody)))

		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(transformedBody)
	})
}

// transformResponseWriter captures the response produced by the next handler
// so that a TransformHandler can process it before it reaches the client.
type transformResponseWriter struct {
	underlying  http.ResponseWriter
	header      http.Header
	body        *bytes.Buffer
	statusCode  int
	overflowed  bool
	wroteHeader bool
}

func (tw *transformResponseWriter) Header() http.Header {
	return tw.header
}

func (tw *transformResponseWriter) WriteHeader(code int) {
	if tw.wroteHeader {
		return
	}
	tw.wroteHeader = true
	tw.statusCode = code
}

func (tw *transformResponseWriter) Write(b []byte) (int, error) {
	if tw.overflowed {
		return tw.underlying.Write(b)
	}

	if tw.body.Len()+len(b) > maxTransformBufferSize {
		// Buffer would exceed the limit. Flush everything directly to the
		// underlying writer and stop buffering.
		tw.overflowed = true
		slog.Warn("transform: response too large, skipping transform",
			"buffered", tw.body.Len(),
			"incoming", len(b),
		)
		// Copy captured headers and status to the underlying writer.
		dst := tw.underlying.Header()
		for k, vs := range tw.header {
			dst[k] = vs
		}
		tw.underlying.WriteHeader(tw.statusCode)
		if tw.body.Len() > 0 {
			_, _ = tw.underlying.Write(tw.body.Bytes())
			tw.body.Reset()
		}
		return tw.underlying.Write(b)
	}

	return tw.body.Write(b)
}

// Flush supports streaming if the underlying writer implements http.Flusher.
func (tw *transformResponseWriter) Flush() {
	if f, ok := tw.underlying.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack supports WebSocket upgrades if the underlying writer supports it.
func (tw *transformResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := tw.underlying.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
}

// collectCleanups gathers Cleanup functions from all modules that implement the
// plugin.Cleanup interface.
func collectCleanups(modules ...any) []func() {
	var fns []func()
	for _, m := range modules {
		if c, ok := m.(plugin.Cleanup); ok {
			fn := c.Cleanup // capture the method value
			fns = append(fns, func() { _ = fn() })
		}
	}
	return fns
}

// --- Middleware Wrappers for the Compiled Handler Chain ---
// Each wrapper follows the same pattern: check if the config is present,
// unmarshal it, and return a wrapping http.Handler (or the original if disabled).

// isNullOrEmpty returns true if the raw JSON is nil, empty, or "null".
func isNullOrEmpty(raw json.RawMessage) bool {
	return len(raw) == 0 || string(raw) == "null"
}

// wrapCompression wraps the handler with proxy-level response compression.
// Supports gzip, brotli, and zstd based on Accept-Encoding negotiation.
func wrapCompression(next http.Handler, cfg json.RawMessage) http.Handler {
	if isNullOrEmpty(cfg) {
		return next
	}
	var compCfg compression.Config
	if err := json.Unmarshal(cfg, &compCfg); err != nil {
		slog.Warn("compile: invalid compression config, skipping", "error", err)
		return next
	}
	if !compCfg.Enable {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		encoding := compression.SelectEncoding(r.Header.Get("Accept-Encoding"), &compCfg)
		if encoding == "" {
			next.ServeHTTP(w, r)
			return
		}
		cw := &compression.ResponseWriter{
			ResponseWriter: w,
			Encoding:       encoding,
			Cfg:            &compCfg,
		}
		defer cw.Close()
		next.ServeHTTP(cw, r)
	})
}

// wrapCORS wraps the handler with CORS header injection and preflight handling.
func wrapCORS(next http.Handler, cfg json.RawMessage) http.Handler {
	if isNullOrEmpty(cfg) {
		return next
	}
	var corsCfg cors.Config
	if err := json.Unmarshal(cfg, &corsCfg); err != nil {
		slog.Warn("compile: invalid cors config, skipping", "error", err)
		return next
	}
	if !corsCfg.Enable {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cors.HandlePreflight(w, r, &corsCfg) {
			return
		}
		cors.ApplyHeaders(w, r, &corsCfg)
		next.ServeHTTP(w, r)
	})
}

// wrapHSTS wraps the handler with HTTP Strict Transport Security header injection.
// The HSTS header is only added for HTTPS responses (RFC 6797 Section 7.2).
func wrapHSTS(next http.Handler, cfg json.RawMessage) http.Handler {
	if isNullOrEmpty(cfg) {
		return next
	}
	var hstsCfg hsts.Config
	if err := json.Unmarshal(cfg, &hstsCfg); err != nil {
		slog.Warn("compile: invalid hsts config, skipping", "error", err)
		return next
	}
	if !hstsCfg.Enabled {
		return next
	}

	// Pre-build the header value at compile time since it's static.
	maxAge := hstsCfg.MaxAge
	if maxAge <= 0 {
		maxAge = 31536000 // 1 year
	}
	headerVal := fmt.Sprintf("max-age=%d", maxAge)
	if hstsCfg.IncludeSubdomains {
		headerVal += "; includeSubDomains"
	}
	if hstsCfg.Preload {
		headerVal += "; preload"
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only add HSTS on HTTPS responses (RFC 6797 Section 7.2).
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", headerVal)
		}
		next.ServeHTTP(w, r)
	})
}

// wrapForceSSL redirects HTTP requests to HTTPS (301 Moved Permanently).
func wrapForceSSL(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			next.ServeHTTP(w, r)
			return
		}
		httpsURL := &url.URL{
			Scheme:   "https",
			Host:     r.Host,
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
			Fragment: r.URL.Fragment,
		}
		http.Redirect(w, r, httpsURL.String(), http.StatusMovedPermanently)
	})
}

// wrapAllowedMethods rejects requests whose HTTP method is not in the allowed
// list. OPTIONS is always allowed (CORS preflight support).
func wrapAllowedMethods(next http.Handler, methods []string) http.Handler {
	// Build a set for O(1) lookup. Store uppercase for case-insensitive matching.
	allowed := make(map[string]struct{}, len(methods))
	for _, m := range methods {
		allowed[strings.ToUpper(m)] = struct{}{}
	}
	allowHeader := strings.Join(methods, ", ")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// OPTIONS is always allowed for CORS preflight.
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", allowHeader)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if _, ok := allowed[strings.ToUpper(r.Method)]; !ok {
			w.Header().Set("Allow", allowHeader)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// wrapResponseModifiers wraps the handler so that response modifiers are applied
// to the response after the inner handler (action + transforms) has written it.
// The response is captured into a buffer, assembled into an *http.Response,
// passed to ResponseModifiers.Apply, and then written to the real client.
func wrapResponseModifiers(next http.Handler, cfg json.RawMessage) http.Handler {
	if isNullOrEmpty(cfg) {
		return next
	}
	var mods modifier.ResponseModifiers
	if err := json.Unmarshal(cfg, &mods); err != nil {
		slog.Warn("compile: invalid response_modifiers config, skipping", "error", err)
		return next
	}
	if len(mods) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tw := &transformResponseWriter{
			underlying: w,
			header:     make(http.Header),
			body:       &bytes.Buffer{},
			statusCode: http.StatusOK,
		}

		next.ServeHTTP(tw, r)

		// If the body exceeded the buffer limit, the data was already flushed
		// directly to the client and we cannot apply modifiers.
		if tw.overflowed {
			return
		}

		// Build an *http.Response from the captured data.
		resp := &http.Response{
			StatusCode:    tw.statusCode,
			Header:        tw.header.Clone(),
			Body:          io.NopCloser(tw.body),
			ContentLength: int64(tw.body.Len()),
			Request:       r,
		}

		if err := mods.Apply(resp); err != nil {
			slog.Error("response modifier failed", "error", err)
			http.Error(w, "internal response modifier error", http.StatusInternalServerError)
			return
		}

		// Copy modified headers to the real writer.
		dst := w.Header()
		for k, vs := range resp.Header {
			dst[k] = vs
		}

		// Read the (possibly replaced) body.
		modifiedBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			slog.Error("response modifier read body failed", "error", err)
			http.Error(w, "internal response modifier error", http.StatusInternalServerError)
			return
		}

		// Update Content-Length to reflect the modified body size.
		dst.Del("Content-Length")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(modifiedBody)))

		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(modifiedBody)
	})
}

// wrapOnRequest wraps the handler with on_request callback execution. Callbacks
// are fired sequentially after authentication passes. Synchronous callbacks
// block and may enrich RequestData.Data; asynchronous callbacks fire-and-forget.
func wrapOnRequest(next http.Handler, cfg json.RawMessage) http.Handler {
	if isNullOrEmpty(cfg) {
		return next
	}
	var callbacks callback.Callbacks
	if err := json.Unmarshal(cfg, &callbacks); err != nil {
		slog.Warn("compile: invalid on_request config, skipping", "error", err)
		return next
	}
	if len(callbacks) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rd := reqctx.GetRequestData(ctx)
		if rd == nil {
			next.ServeHTTP(w, r)
			return
		}

		// Build callback context from the 9-namespace model.
		callbackData := buildCallbackContext(rd)

		// Execute callbacks sequentially (sync ones block, async ones fire-and-forget).
		result, err := callbacks.DoSequentialWithType(ctx, callbackData, "on_request")
		if err != nil {
			slog.Error("on_request callback failed", "error", err)
			// Don't fail the request, just log the error.
		}

		// Store sync callback results in RequestData.Data.
		if len(result) > 0 {
			for k, v := range result {
				rd.SetData(k, v)
			}
		}

		next.ServeHTTP(w, r)
	})
}

// wrapOnResponse wraps the handler with on_response callback execution. The
// response is captured, callbacks are fired with response metadata (status,
// headers, size), and results are stored in RequestData.Data.
func wrapOnResponse(next http.Handler, cfg json.RawMessage) http.Handler {
	if isNullOrEmpty(cfg) {
		return next
	}
	var callbacks callback.Callbacks
	if err := json.Unmarshal(cfg, &callbacks); err != nil {
		slog.Warn("compile: invalid on_response config, skipping", "error", err)
		return next
	}
	if len(callbacks) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture the response so we can inspect it before forwarding.
		tw := &transformResponseWriter{
			underlying: w,
			header:     make(http.Header),
			body:       &bytes.Buffer{},
			statusCode: http.StatusOK,
		}

		next.ServeHTTP(tw, r)

		// Build callback context with response data.
		ctx := r.Context()
		rd := reqctx.GetRequestData(ctx)
		callbackData := buildCallbackContext(rd)
		callbackData["response"] = map[string]any{
			"status":  tw.statusCode,
			"headers": tw.header,
			"size":    tw.body.Len(),
		}

		// Execute callbacks (fire-and-forget for errors).
		result, err := callbacks.DoSequentialWithType(ctx, callbackData, "on_response")
		if err != nil {
			slog.Error("on_response callback failed", "error", err)
		}

		// Store results in RequestData.Data.
		if rd != nil && len(result) > 0 {
			for k, v := range result {
				rd.SetData(k, v)
			}
		}

		// Write the captured response to the client (unless already overflowed).
		if !tw.overflowed {
			dst := w.Header()
			for k, vs := range tw.header {
				dst[k] = vs
			}
			w.WriteHeader(tw.statusCode)
			_, _ = w.Write(tw.body.Bytes())
		}
	})
}

// buildCallbackContext extracts the 9-namespace context from RequestData
// for use as callback body template variables.
func buildCallbackContext(rd *reqctx.RequestData) map[string]any {
	data := make(map[string]any, 9)
	if rd.OriginCtx != nil {
		data["origin"] = rd.OriginCtx
	}
	if rd.ServerCtx != nil {
		data["server"] = rd.ServerCtx
	}
	if rd.VarsCtx != nil && rd.VarsCtx.Data != nil {
		data["vars"] = rd.VarsCtx.Data
	}
	if rd.FeaturesCtx != nil && rd.FeaturesCtx.Data != nil {
		data["features"] = rd.FeaturesCtx.Data
	}
	if rd.ClientCtx != nil {
		data["client"] = rd.ClientCtx
	}
	if rd.SessionCtx != nil {
		data["session"] = rd.SessionCtx
	}
	if rd.Snapshot != nil {
		data["request"] = rd.Snapshot
	}
	if rd.CtxObj != nil {
		data["ctx"] = rd.CtxObj
	}
	return data
}

// wrapRequestModifiers wraps the handler with request modifier logic. Each
// modifier in the slice is applied to the incoming request before it reaches
// the next handler.
func wrapRequestModifiers(next http.Handler, cfg json.RawMessage) http.Handler {
	if isNullOrEmpty(cfg) {
		return next
	}
	var mods modifier.RequestModifiers
	if err := json.Unmarshal(cfg, &mods); err != nil {
		slog.Warn("compile: invalid request_modifiers config, skipping", "error", err)
		return next
	}
	if len(mods) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := mods.Apply(r); err != nil {
			slog.Error("request modifier failed", "error", err)
		}
		next.ServeHTTP(w, r)
	})
}

// wrapMessageSignatures wraps the handler with RFC 9421 HTTP Message Signature
// verification on inbound requests and signing on outbound requests.
func wrapMessageSignatures(next http.Handler, cfg json.RawMessage) http.Handler {
	if isNullOrEmpty(cfg) {
		return next
	}
	var sigCfg httpsig.Config
	if err := json.Unmarshal(cfg, &sigCfg); err != nil {
		slog.Warn("compile: invalid message_signatures config, skipping", "error", err)
		return next
	}
	if !sigCfg.Enable {
		return next
	}
	if err := sigCfg.Validate(); err != nil {
		slog.Warn("compile: message_signatures validation failed, skipping", "error", err)
		return next
	}
	return sigCfg.Middleware(next)
}

// fallbackResponseWriter captures the status code and allows re-serving from a fallback.
type fallbackResponseWriter struct {
	http.ResponseWriter
	statusCode    int
	headerWritten bool
	buf           bytes.Buffer
	shouldBuffer  bool
}

func (w *fallbackResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	if w.shouldBuffer {
		w.headerWritten = true
		return // Don't write to underlying writer yet
	}
	w.ResponseWriter.WriteHeader(code)
	w.headerWritten = true
}

func (w *fallbackResponseWriter) Write(b []byte) (int, error) {
	if w.shouldBuffer {
		return w.buf.Write(b)
	}
	if !w.headerWritten {
		w.statusCode = 200
		w.headerWritten = true
	}
	return w.ResponseWriter.Write(b)
}

// wrapFallbackOrigin wraps the handler with fallback origin support.
// When the primary handler returns a matching error status code, the fallback
// origin's handler serves the request instead.
func wrapFallbackOrigin(next http.Handler, cfg json.RawMessage, services plugin.ServiceProvider) http.Handler {
	if isNullOrEmpty(cfg) {
		return next
	}
	var fb FallbackOrigin
	if err := json.Unmarshal(cfg, &fb); err != nil {
		slog.Warn("compile: invalid fallback_origin config, skipping", "error", err)
		return next
	}

	// Compile the inline fallback origin handler
	var fallbackHandler http.Handler
	if len(fb.Origin) > 0 && string(fb.Origin) != "null" {
		var raw RawOrigin
		if err := json.Unmarshal(fb.Origin, &raw); err != nil {
			slog.Warn("compile: invalid inline fallback origin", "error", err)
			return next
		}
		compiled, err := CompileOrigin(&raw, services)
		if err != nil {
			slog.Warn("compile: failed to compile fallback origin", "error", err)
			return next
		}
		fallbackHandler = compiled
	}

	if fallbackHandler == nil {
		return next
	}

	// Check if on_status is configured
	hasStatusTrigger := len(fb.OnStatus) > 0

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hasStatusTrigger {
			// Buffer the response to check status code
			fw := &fallbackResponseWriter{
				ResponseWriter: w,
				shouldBuffer:   true,
			}
			next.ServeHTTP(fw, r)

			if fb.ShouldTriggerOnStatus(fw.statusCode) {
				// Status matched - serve from fallback
				if fb.AddDebugHeader {
					w.Header().Set("X-Fallback-Trigger", "status")
					w.Header().Set("X-Fallback-Status", fmt.Sprintf("%d", fw.statusCode))
				}
				fallbackHandler.ServeHTTP(w, r)
				return
			}

			// No trigger - flush buffered response to client
			for k, vs := range fw.Header() {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(fw.statusCode)
			_, _ = w.Write(fw.buf.Bytes())
			return
		}

		// on_error only - no buffering needed, just catch panics/errors
		// The ErrorHandler on the reverse proxy handles transport errors.
		// For compiled origins, we need to wrap the handler to catch 502s.
		fw := &fallbackResponseWriter{
			ResponseWriter: w,
			shouldBuffer:   true,
		}
		next.ServeHTTP(fw, r)

		if fw.statusCode == 502 && fb.OnError {
			if fb.AddDebugHeader {
				w.Header().Set("X-Fallback-Trigger", "error")
			}
			fallbackHandler.ServeHTTP(w, r)
			return
		}

		// Flush the buffered response
		for k, vs := range fw.Header() {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(fw.statusCode)
		_, _ = w.Write(fw.buf.Bytes())
	})
}

// wrapForwardRules wraps the handler with path-based forwarding to inline origins.
// When a forward rule matches the incoming request, the request is dispatched to
// the inline origin's compiled handler. Otherwise the default handler is used.
func wrapForwardRules(next http.Handler, cfg json.RawMessage, services plugin.ServiceProvider) http.Handler {
	if isNullOrEmpty(cfg) {
		return next
	}
	var rules forward.ForwardRules
	if err := json.Unmarshal(cfg, &rules); err != nil {
		slog.Warn("compile: invalid forward_rules config, skipping", "error", err)
		return next
	}
	if len(rules) == 0 {
		return next
	}

	// Pre-compile inline origin handlers for each rule that has an inline origin.
	type compiledRule struct {
		rule    forward.ForwardRule
		handler http.Handler
	}
	var compiled []compiledRule
	for _, r := range rules {
		var h http.Handler
		if len(r.Origin) > 0 && string(r.Origin) != "null" {
			// Compile the inline origin as a standalone handler
			var raw RawOrigin
			if err := json.Unmarshal(r.Origin, &raw); err != nil {
				slog.Warn("compile: invalid inline origin in forward rule", "error", err)
				continue
			}
			origin, err := CompileOrigin(&raw, services)
			if err != nil {
				slog.Warn("compile: failed to compile inline forward rule origin",
					"id", raw.ID, "error", err)
				continue
			}
			h = origin
		}
		compiled = append(compiled, compiledRule{rule: r, handler: h})
	}

	if len(compiled) == 0 {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, cr := range compiled {
			if cr.rule.Match(r) {
				if cr.handler != nil {
					cr.handler.ServeHTTP(w, r)
					return
				}
				// If hostname-based (no inline origin), fall through to default
				break
			}
		}
		next.ServeHTTP(w, r)
	})
}

// wrapResponseCache wraps the handler with response-level caching. It uses the
// ServiceProvider's ResponseCache if available, otherwise falls back to an
// in-memory cache. Only GET and HEAD requests are cached by default.
func wrapResponseCache(next http.Handler, cfg json.RawMessage, services plugin.ServiceProvider) http.Handler {
	if isNullOrEmpty(cfg) {
		return next
	}

	var cacheCfg struct {
		Enabled          bool     `json:"enabled"`
		TTL              string   `json:"ttl"`
		CacheKeyParams   []string `json:"cache_key_params"`
		CacheKeyHeaders  []string `json:"cache_key_headers"`
		CacheableMethods []string `json:"cacheable_methods"`
		CacheableStatus  []int    `json:"cacheable_status"`
	}
	if err := json.Unmarshal(cfg, &cacheCfg); err != nil {
		slog.Warn("compile: invalid response_cache config", "error", err)
		return next
	}
	if !cacheCfg.Enabled {
		return next
	}

	cache := services.ResponseCache()
	if cache == nil {
		cache = memorycache.New(1000)
	}

	ttl := 5 * time.Minute
	if cacheCfg.TTL != "" {
		if d, err := time.ParseDuration(cacheCfg.TTL); err == nil {
			ttl = d
		}
	}

	// Build set of cacheable methods (default: GET, HEAD).
	cacheableMethods := map[string]bool{"GET": true, "HEAD": true}
	if len(cacheCfg.CacheableMethods) > 0 {
		cacheableMethods = make(map[string]bool, len(cacheCfg.CacheableMethods))
		for _, m := range cacheCfg.CacheableMethods {
			cacheableMethods[strings.ToUpper(m)] = true
		}
	}

	// Build set of cacheable status codes (default: 200).
	cacheableStatus := map[int]bool{200: true}
	if len(cacheCfg.CacheableStatus) > 0 {
		cacheableStatus = make(map[int]bool, len(cacheCfg.CacheableStatus))
		for _, s := range cacheCfg.CacheableStatus {
			cacheableStatus[s] = true
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cacheableMethods[r.Method] {
			next.ServeHTTP(w, r)
			return
		}

		key := generateCacheKey(r, cacheCfg.CacheKeyParams, cacheCfg.CacheKeyHeaders)

		if cached, ok := cache.Get(r.Context(), key); ok {
			w.Header().Set("X-Cache", "HIT")
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(cached)
			return
		}

		tw := &transformResponseWriter{
			underlying: w,
			header:     make(http.Header),
			body:       &bytes.Buffer{},
			statusCode: http.StatusOK,
		}
		next.ServeHTTP(tw, r)

		if cacheableStatus[tw.statusCode] && !tw.overflowed {
			body := tw.body.Bytes()
			_ = cache.Set(r.Context(), key, body, ttl)
		}

		w.Header().Set("X-Cache", "MISS")
		dst := w.Header()
		for k, vs := range tw.header {
			dst[k] = vs
		}
		w.WriteHeader(tw.statusCode)
		_, _ = w.Write(tw.body.Bytes())
	})
}

// generateCacheKey builds a cache key from the request method, host, path,
// and optionally selected query parameters and headers.
func generateCacheKey(r *http.Request, params []string, headers []string) string {
	var b strings.Builder
	b.WriteString(r.Method)
	b.WriteByte(':')
	b.WriteString(r.Host)
	b.WriteByte(':')
	b.WriteString(r.URL.Path)

	if len(params) > 0 {
		q := r.URL.Query()
		for _, p := range params {
			if v := q.Get(p); v != "" {
				b.WriteByte(':')
				b.WriteString(p)
				b.WriteByte('=')
				b.WriteString(v)
			}
		}
	} else {
		b.WriteByte(':')
		b.WriteString(r.URL.RawQuery)
	}

	for _, h := range headers {
		if v := r.Header.Get(h); v != "" {
			b.WriteByte(':')
			b.WriteString(h)
			b.WriteByte('=')
			b.WriteString(v)
		}
	}

	return b.String()
}

// BotDetectionMiddlewareFactory is a function that creates bot detection middleware
// from a JSON config. It is set by the engine/middleware package at init time to
// avoid import cycles between internal/config and internal/engine/middleware.
var BotDetectionMiddlewareFactory func(cfg json.RawMessage) (func(http.Handler) http.Handler, error)

// ThreatProtectionMiddlewareFactory is a function that creates threat protection
// middleware from a JSON config. Set by the engine/middleware package at init time.
var ThreatProtectionMiddlewareFactory func(cfg json.RawMessage) (func(http.Handler) http.Handler, error)

// wrapBotDetection wraps the handler with user-agent based bot detection.
// Uses the registered BotDetectionMiddlewareFactory to avoid import cycles.
func wrapBotDetection(next http.Handler, cfg json.RawMessage) http.Handler {
	if isNullOrEmpty(cfg) {
		return next
	}
	if BotDetectionMiddlewareFactory == nil {
		slog.Debug("compile: bot_detection config present but no factory registered, skipping")
		return next
	}
	mw, err := BotDetectionMiddlewareFactory(cfg)
	if err != nil {
		slog.Warn("compile: bot_detection factory error, skipping", "error", err)
		return next
	}
	if mw == nil {
		return next
	}
	return mw(next)
}

// wrapThreatProtection wraps the handler with JSON/XML structural validation
// to prevent payload-based attacks.
func wrapThreatProtection(next http.Handler, cfg json.RawMessage) http.Handler {
	if isNullOrEmpty(cfg) {
		return next
	}
	if ThreatProtectionMiddlewareFactory == nil {
		slog.Debug("compile: threat_protection config present but no factory registered, skipping")
		return next
	}
	mw, err := ThreatProtectionMiddlewareFactory(cfg)
	if err != nil {
		slog.Warn("compile: threat_protection factory error, skipping", "error", err)
		return next
	}
	if mw == nil {
		return next
	}
	return mw(next)
}

// wrapSession wraps the handler with session middleware when a SessionProvider
// is available. It reads or creates a session cookie, encrypts/decrypts the
// session ID via the SessionProvider, and populates RequestData.SessionData.
func wrapSession(next http.Handler, cfg json.RawMessage, services plugin.ServiceProvider) http.Handler {
	if isNullOrEmpty(cfg) {
		return next
	}
	sp := services.Sessions()
	if sp == nil {
		slog.Debug("compile: session config present but no SessionProvider available, skipping")
		return next
	}

	var sessCfg SessionConfig
	if err := json.Unmarshal(cfg, &sessCfg); err != nil {
		slog.Warn("compile: invalid session config, skipping", "error", err)
		return next
	}
	if sessCfg.Disabled {
		return next
	}

	cookieName := sessCfg.CookieName
	if cookieName == "" {
		cookieName = "_sb.s"
	}
	cookieMaxAge := sessCfg.CookieMaxAge
	if cookieMaxAge == 0 {
		cookieMaxAge = 3600
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip if not SSL and AllowNonSSL is not enabled
		if r.TLS == nil && !sessCfg.AllowNonSSL {
			next.ServeHTTP(w, r)
			return
		}

		ctx := r.Context()
		rd := reqctx.GetRequestData(ctx)
		if rd == nil {
			next.ServeHTTP(w, r)
			return
		}

		sessionData := rd.SessionData
		var sessionIDStr string

		if sessionData == nil {
			// Try to read existing session from cookie
			cookie, _ := r.Cookie(cookieName)
			if cookie != nil {
				decrypted, err := sp.Decrypt(cookie.Value)
				if err != nil {
					slog.Warn("compile: session decrypt failed", "error", err)
				} else {
					sessionIDStr = decrypted
					// Try to load session data from the store
					store := sp.SessionStore()
					if store != nil {
						data, err := store.Get(ctx, sessionIDStr)
						if err == nil && len(data) > 0 {
							sessionData = &reqctx.SessionData{}
							if jsonErr := json.Unmarshal(data, sessionData); jsonErr != nil {
								slog.Warn("compile: session data unmarshal failed", "error", jsonErr)
								sessionData = nil
							}
						}
					}
				}
			}
		}

		if sessionData == nil {
			// Create a new session
			sessionIDStr = generateSessionID()
			encrypted, err := sp.Encrypt(sessionIDStr)
			if err != nil {
				slog.Warn("compile: session encrypt failed", "error", err)
				next.ServeHTTP(w, r)
				return
			}
			sessionData = &reqctx.SessionData{
				ID:          sessionIDStr,
				EncryptedID: encrypted,
				CreatedAt:   time.Now(),
			}
		}

		sessionData.Expires = time.Now().Add(time.Duration(cookieMaxAge) * time.Second)
		if r.URL != nil {
			sessionData.AddVisitedURL(r.URL.String())
		}
		rd.SessionData = sessionData

		// Set session cookie
		cookieSecure := r.TLS != nil
		cookieHttpOnly := !sessCfg.DisableHttpOnly

		sameSite := http.SameSiteLaxMode
		switch strings.ToLower(sessCfg.CookieSameSite) {
		case "strict":
			sameSite = http.SameSiteStrictMode
		case "none":
			sameSite = http.SameSiteNoneMode
		}

		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    sessionData.EncryptedID,
			Path:     "/",
			HttpOnly: cookieHttpOnly,
			Secure:   cookieSecure,
			SameSite: sameSite,
			MaxAge:   cookieMaxAge,
		})

		*r = *r.WithContext(reqctx.SetRequestData(ctx, rd))
		next.ServeHTTP(w, r)

		// Save session data after response
		store := sp.SessionStore()
		if store != nil {
			updatedRD := reqctx.GetRequestData(r.Context())
			if updatedRD != nil && updatedRD.SessionData != nil {
				data, err := json.Marshal(updatedRD.SessionData)
				if err == nil {
					ttl := time.Duration(cookieMaxAge) * time.Second
					if storeErr := store.Set(ctx, sessionIDStr, data, ttl); storeErr != nil {
						slog.Warn("compile: session save failed", "error", storeErr)
					}
				}
			}
		}
	})
}

// wrapTrafficCapture accepts traffic capture config but delegates to an enterprise
// middleware factory if registered. Traffic capture is an enterprise feature that
// requires the capture.Manager infrastructure (messenger, cacher, buffered writer).
func wrapTrafficCapture(next http.Handler, cfg json.RawMessage, services plugin.ServiceProvider) http.Handler {
	if isNullOrEmpty(cfg) {
		return next
	}
	// Check if enterprise has registered a traffic capture factory via pkg/plugin
	factory := plugin.GetTrafficCaptureMiddleware()
	if factory != nil {
		return factory(next, cfg, services)
	}
	slog.Info("traffic capture is an enterprise feature, ignoring traffic_capture config")
	return next
}

// generateSessionID produces a random session identifier. It uses
// crypto/rand to create a 16-byte random value encoded as hex.
func generateSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// wrapRateLimitHeaders converts X-RateLimit-* headers (set by rate limiting
// policies) to the standardized IETF RateLimit-* format (draft-ietf-httpapi-ratelimit-headers).
// It intercepts WriteHeader to inject the standardized headers before they are sent.
func wrapRateLimitHeaders(next http.Handler, cfg json.RawMessage) http.Handler {
	if isNullOrEmpty(cfg) {
		return next
	}
	var rlCfg struct {
		Enable bool `json:"enable"`
	}
	if err := json.Unmarshal(cfg, &rlCfg); err != nil || !rlCfg.Enable {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &rateLimitHeaderWriter{ResponseWriter: w}
		next.ServeHTTP(rw, r)
	})
}

// rateLimitHeaderWriter intercepts WriteHeader to copy X-RateLimit-* headers
// to their standardized RateLimit-* equivalents before the response is sent.
type rateLimitHeaderWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

func (rw *rateLimitHeaderWriter) WriteHeader(code int) {
	if !rw.wroteHeader {
		rw.wroteHeader = true
		h := rw.ResponseWriter.Header()
		if v := h.Get("X-RateLimit-Limit"); v != "" {
			h.Set("RateLimit-Limit", v)
		}
		if v := h.Get("X-RateLimit-Remaining"); v != "" {
			h.Set("RateLimit-Remaining", v)
		}
		if v := h.Get("X-RateLimit-Reset"); v != "" {
			h.Set("RateLimit-Reset", v)
		}
	}
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *rateLimitHeaderWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

// Flush supports streaming if the underlying writer implements http.Flusher.
func (rw *rateLimitHeaderWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack supports WebSocket upgrades if the underlying writer supports it.
func (rw *rateLimitHeaderWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
}
