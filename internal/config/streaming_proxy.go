// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	httputilstd "net/http/httputil"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	transportpkg "github.com/soapbucket/sbproxy/internal/engine/transport"
	"github.com/soapbucket/sbproxy/internal/version"
)

// StreamingProxyHandler replaces httputil.ReverseProxy with full streaming control
type StreamingProxyHandler struct {
	config                 *Config
	flushController        *FlushController
	responseCopier         *ResponseCopier
	protocolDetector       *ProtocolDetector
	trustValidator         *TrustValidator
	clientHeaderStripper   *HeaderMatcher
	internalHeaderStripper *HeaderMatcher
	shadowTransport        *transportpkg.ShadowTransport
}

// NewStreamingProxyHandler creates a new streaming-aware reverse proxy handler
func NewStreamingProxyHandler(cfg *Config) *StreamingProxyHandler {
	proxyHeaders := cfg.GetProxyHeaders()

	// Initialize trust validator
	trustValidator, err := NewTrustValidator(
		proxyHeaders.TrustMode,
		proxyHeaders.TrustedProxies,
		proxyHeaders.TrustedHops,
	)
	if err != nil {
		slog.Error("failed to create trust validator", "error", err, "config_id", cfg.ID)
		// Fall back to trust all
		trustValidator, _ = NewTrustValidator(TrustAll, nil, 0)
	}

	var clientHeaderStripper *HeaderMatcher
	if len(proxyHeaders.StripClientHeaders) > 0 {
		clientHeaderStripper = NewHeaderMatcher(proxyHeaders.StripClientHeaders)
	}

	var internalHeaderStripper *HeaderMatcher
	if len(proxyHeaders.StripInternalHeaders) > 0 {
		internalHeaderStripper = NewHeaderMatcher(proxyHeaders.StripInternalHeaders)
	}

	// Extract shadow transport from action if it's a Proxy
	var shadowTransport *transportpkg.ShadowTransport
	if proxyAction, ok := cfg.action.(*Proxy); ok {
		shadowTransport = proxyAction.ShadowTransport()
	}

	return &StreamingProxyHandler{
		config:                 cfg,
		flushController:        NewFlushController(),
		responseCopier:         NewResponseCopier(),
		protocolDetector:       NewProtocolDetector(),
		trustValidator:         trustValidator,
		clientHeaderStripper:   clientHeaderStripper,
		internalHeaderStripper: internalHeaderStripper,
		shadowTransport:        shadowTransport,
	}
}

// ServeHTTP implements http.Handler
func (h *StreamingProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	proto := h.getProxyProtocolOrDefault()

	// RFC 8470: Early data handling - reject non-idempotent 0-RTT requests
	if handleEarlyData(w, r, proto.EarlyData, h.config.ProblemDetails) {
		return
	}

	// CORS preflight handling - must be before other checks
	if handleCORSPreflight(w, r, h.config.CORS) {
		return
	}

	// RFC 9421: Verify inbound request signatures
	if h.config.MessageSignatures != nil && h.config.MessageSignatures.VerifyInbound {
		if err := verifyRequestSignature(r, h.config.MessageSignatures); err != nil {
			h.writeError(w, r, http.StatusUnauthorized, "Invalid or missing message signature")
			return
		}
	}

	// RFC 9110 Section 9.3.8: block TRACE by default (prevents credential leakage)
	if r.Method == http.MethodTrace && !proto.AllowTrace {
		h.writeError(w, r, http.StatusMethodNotAllowed, "TRACE method not allowed")
		return
	}

	// RFC 9112 Section 6.3: reject requests with both Content-Length and Transfer-Encoding
	// to prevent request smuggling attacks
	if !proto.DisableRequestSmuggling && r.Header.Get("Transfer-Encoding") != "" && r.Header.Get("Content-Length") != "" {
		h.writeError(w, r, http.StatusBadRequest, "Bad Request")
		return
	}

	// RFC 9110 Section 7.6.2: handle Max-Forwards for OPTIONS
	if !proto.DisableMaxForwards && r.Method == http.MethodOptions {
		if mf := r.Header.Get("Max-Forwards"); mf != "" {
			if mf == "0" {
				w.Header().Set("Allow", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")
				w.WriteHeader(http.StatusOK)
				return
			}
			val, err := strconv.Atoi(mf)
			if err == nil && val > 0 {
				r.Header.Set("Max-Forwards", strconv.Itoa(val-1))
			}
		}
	}

	// RFC 3986 Section 6: URI normalization
	normalizeRequestURI(r, h.config.URINormalization)

	// Detect protocol and route accordingly
	protocol := h.protocolDetector.Detect(r)

	slog.Debug("streaming proxy handling request",
		"protocol", protocol,
		"method", r.Method,
		"url", r.URL.String(),
		"config_id", h.config.ID)

	// Handle based on protocol
	switch protocol {
	case ProtocolWebSocket:
		h.handleWebSocket(w, r)
	case ProtocolHTTP2Bidirectional:
		h.handleHTTP2Stream(w, r)
	case ProtocolGRPC:
		h.handleGRPC(w, r)
	default:
		h.handleHTTP(w, r)
	}
}

// handleHTTP handles standard HTTP/1.1 and HTTP/2 requests
func (h *StreamingProxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Phase 1: Prepare outgoing request
	outReq := h.prepareRequest(r)

	// Phase 1.5: HTTP Callout for mid-request enrichment (before shadow and roundtrip)
	if h.config.HTTPCallout != nil {
		if err := ExecuteHTTPCallout(h.config.HTTPCallout, outReq); err != nil {
			h.writeError(w, r, http.StatusBadGateway, "Callout service unavailable")
			return
		}
	}

	// Fire shadow asynchronously — Shadow() reads+restores body so RoundTrip can still read it
	if h.shadowTransport != nil {
		h.shadowTransport.Shadow(outReq)
	}

	// Phase 2: Execute request via transport
	resp, err := h.roundTrip(w, outReq)
	if err != nil {
		h.handleError(w, r, err)
		return
	}
	defer resp.Body.Close()

	// Phase 3: Process response (ModifyResponse, transforms, modifiers)
	if err := h.processResponse(resp); err != nil {
		h.handleError(w, r, err)
		return
	}

	// Apply CORS headers to response
	applyCORSHeaders(w, r, h.config.CORS)

	// Phase 4: Determine flush strategy
	flushStrategy := h.flushController.DetermineStrategy(r, resp)

	slog.Debug("flush strategy determined",
		"strategy", flushStrategy.Type,
		"interval", flushStrategy.Interval,
		"reason", flushStrategy.Reason,
		"config_id", h.config.ID)

	// Record flush strategy metric
	configID := h.config.ID
	if configID == "" {
		configID = "unknown"
	}
	metric.FlushStrategyUsage(configID, string(flushStrategy.Type), flushStrategy.Reason)

	// Phase 5: Copy response with appropriate flushing
	// Wrap writer with priority scheduling if configured
	var priorityWriter *PriorityResponseWriter
	if h.config.PriorityScheduler != nil && h.config.PriorityScheduler.Enable {
		priorityWriter = NewPriorityResponseWriter(w, r, h.config.PriorityScheduler)
	}
	baseWriter := http.ResponseWriter(w)
	if priorityWriter != nil {
		baseWriter = priorityWriter
	}
	// Wrap writer with compression if configured
	finalWriter := h.wrapWithCompression(baseWriter, r, resp, flushStrategy)
	if err := h.responseCopier.Copy(finalWriter, resp, flushStrategy); err != nil {
		slog.Error("error copying response", "error", err, "config_id", h.config.ID)
		// Don't call error handler - headers already sent
		// Close compression writer if wrapped
		if cw, ok := finalWriter.(*compressedResponseWriter); ok {
			cw.Close()
		}
		return
	}

	// Close compression writer to flush remaining data
	if cw, ok := finalWriter.(*compressedResponseWriter); ok {
		cw.Close()
	}

	// Phase 6: Record metrics
	h.recordMetrics(r, resp, flushStrategy.IsStreaming)
}

// prepareRequest applies Rewrite, header handling, and RequestModifiers
func (h *StreamingProxyHandler) prepareRequest(r *http.Request) *http.Request {
	// Clone request
	outReq := r.Clone(r.Context())

	// Apply Rewrite function (modifies URL, Host, etc.)
	if h.config.Rewrite() != nil {
		pr := &httputilstd.ProxyRequest{
			In:  r,
			Out: outReq,
		}
		h.config.Rewrite()(pr)
		outReq = pr.Out
	}

	// Remove hop-by-hop headers BEFORE adding proxy headers
	h.removeHopByHopHeaders(outReq.Header)

	// Strip client headers matching patterns (before sending to upstream)
	if h.clientHeaderStripper != nil {
		h.clientHeaderStripper.StripMatchingHeaders(outReq.Header)
	}

	// Add RFC 7239 Forwarded header when enabled. It can optionally add
	// legacy X-Forwarded-* headers as well. Otherwise add the legacy headers
	// directly. DisableForwarded skips all forwarding headers.
	if proxyHeaders := h.getProxyHeadersOrDefault(); !proxyHeaders.DisableForwarded {
		if proxyHeaders.Forwarded != nil && proxyHeaders.Forwarded.Enable {
			h.addForwardedHeader(outReq, r)
		} else {
			h.addProxyHeaders(outReq, r)
		}
	}

	// Add Via header
	h.addViaHeader(outReq, r)

	// Add enrichment headers (opt-in per origin)
	h.addUserAgentHeader(outReq, r)
	h.addLocationHeader(outReq, r)
	h.addSignatureHeader(outReq, r)

	// Apply request modifiers (from existing config system)
	if err := h.config.RequestModifiers.Apply(outReq); err != nil {
		slog.Error("error applying request modifiers", "error", err, "config_id", h.config.ID)
	}

	h.restoreRequiredProtocolHeaders(outReq, r)

	// RFC 9218: Forward Priority header if configured
	forwardHTTPPriority(outReq, r, h.config.HTTPPriority)

	// RFC 8470: Forward Early-Data header if configured
	proto := h.getProxyProtocolOrDefault()
	addEarlyDataHeader(outReq, r, proto.EarlyData)

	// RFC 9110 Section 10.1.1: Handle Expect: 100-continue
	h.handleExpectContinue(outReq, r)

	// RFC 8942: Forward client hint headers to upstream
	forwardClientHints(outReq, r, h.config.ClientHints)

	// RFC 9421: Sign outbound requests
	if h.config.MessageSignatures != nil && h.config.MessageSignatures.SignOutbound {
		if err := signRequest(outReq, h.config.MessageSignatures); err != nil {
			slog.Error("failed to sign outbound request", "error", err, "config_id", h.config.ID)
		}
	}

	return outReq
}

// processResponse applies ModifyResponse (includes transforms and response modifiers)
func (h *StreamingProxyHandler) processResponse(resp *http.Response) error {
	proxyHeaders := h.getProxyHeadersOrDefault()

	// Remove hop-by-hop headers from response (RFC 9110 Section 7.6.1)
	h.removeHopByHopHeaders(resp.Header)

	// Remove server identification headers for security
	if !proxyHeaders.DisableServerHeaderRemoval {
		resp.Header.Del("Server")
		resp.Header.Del("X-Powered-By")
		resp.Header.Del("X-AspNet-Version")
		resp.Header.Del("X-AspNetMvc-Version")
	}

	// Add Via header to response (RFC 9110 Section 7.6.3)
	h.addViaHeaderToResponse(resp)

	// Ensure Date header is present (RFC 9110 Section 6.6.1)
	proto := h.getProxyProtocolOrDefault()
	if !proto.DisableAutoDate && resp.Header.Get("Date") == "" {
		resp.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	}

	// Strip internal headers matching patterns (before sending to client)
	if h.internalHeaderStripper != nil {
		h.internalHeaderStripper.StripMatchingHeaders(resp.Header)
	}

	// RFC 6797: HSTS header injection
	applyHSTSHeader(resp, resp.Request, h.config.HSTS)

	// RFC 9209: Proxy-Status header
	applyProxyStatusHeader(resp, h.config.ProxyStatus)

	// RFC 8942: Client hints response headers
	applyClientHintsHeaders(resp, h.config.ClientHints)

	// Apply ModifyResponse (includes transforms and response modifiers)
	if h.config.ModifyResponse() != nil {
		if err := h.config.ModifyResponse()(resp); err != nil {
			return err
		}
	}

	return nil
}

// writeError writes an error response, using RFC 9457 problem details if configured.
func (h *StreamingProxyHandler) writeError(w http.ResponseWriter, r *http.Request, statusCode int, detail string) {
	// Add Proxy-Status error header if configured
	if h.config.ProxyStatus != nil && h.config.ProxyStatus.Enable {
		proxyName := h.config.ProxyStatus.ProxyName
		if proxyName == "" {
			proxyName = "soapbucket"
		}
		applyProxyStatusErrorHeader(w, &ProxyStatusError{
			ProxyName: proxyName,
			ErrorType: classifyProxyError(detail),
			Detail:    detail,
		})
	}

	writeProblemDetail(w, r, statusCode, detail, h.config.ProblemDetails)
}

// wrapWithCompression wraps the response writer with compression if configured.
func (h *StreamingProxyHandler) wrapWithCompression(w http.ResponseWriter, r *http.Request, resp *http.Response, fs FlushStrategy) http.ResponseWriter {
	cfg := h.config.Compression
	if cfg == nil || !cfg.Enable {
		return w
	}

	// Don't compress true real-time streaming responses (SSE, gRPC) where
	// byte-level latency matters more than bandwidth.
	// Chunked transfer encoding alone does not mean the response is a real-time stream.
	ct := resp.Header.Get("Content-Type")
	if fs.Type == FlushImmediate && (strings.HasPrefix(ct, "text/event-stream") || strings.HasPrefix(ct, "application/grpc")) {
		return w
	}

	// Select encoding based on client's Accept-Encoding
	encoding := selectEncoding(r.Header.Get("Accept-Encoding"), cfg)
	if encoding == "" {
		return w
	}

	return &compressedResponseWriter{
		ResponseWriter: w,
		encoding:       encoding,
		config:         cfg,
	}
}

// handleExpectContinue handles the Expect: 100-continue header per RFC 9110 Section 10.1.1.
func (h *StreamingProxyHandler) handleExpectContinue(outReq *http.Request, clientReq *http.Request) {
	proto := h.getProxyProtocolOrDefault()
	cfg := proto.ExpectContinue
	if cfg == nil {
		return // default: let Go handle it implicitly
	}

	expect := clientReq.Header.Get("Expect")
	if !strings.EqualFold(expect, "100-continue") {
		return
	}

	switch cfg.Mode {
	case "strip":
		outReq.Header.Del("Expect")
	case "absorb":
		outReq.Header.Del("Expect")
		// Go's transport will not send 100-continue to upstream
	case "forward":
		// Keep Expect header for upstream to handle (default Go behavior)
	}
}

// handleError delegates to config's error handler
func (h *StreamingProxyHandler) handleError(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("proxy request failed", "error", err, "url", r.URL.String(), "config_id", h.config.ID)

	// Record error metrics
	configID := h.config.ID
	if configID == "" {
		configID = "unknown"
	}

	// Determine error type
	errorType := "transport_error"
	errorCategory := "transport_error"
	errStr := err.Error()
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline") {
		errorType = "timeout"
	} else if strings.Contains(errStr, "connection") || strings.Contains(errStr, "refused") {
		errorType = "connection_error"
	} else if strings.Contains(errStr, "certificate") || strings.Contains(errStr, "TLS") {
		errorType = "tls_error"
	}

	metric.ErrorTotal(configID, errorType, errorCategory)

	// RFC 9209: Add Proxy-Status error header
	if h.config.ProxyStatus != nil && h.config.ProxyStatus.Enable {
		proxyName := h.config.ProxyStatus.ProxyName
		if proxyName == "" {
			proxyName = "soapbucket"
		}
		applyProxyStatusErrorHeader(w, &ProxyStatusError{
			ProxyName: proxyName,
			ErrorType: classifyProxyError(errStr),
			Detail:    errStr,
		})
	}

	// Use config's error handler
	if h.config.ErrorHandler() != nil {
		h.config.ErrorHandler()(w, r, err)
	} else {
		writeProblemDetail(w, r, http.StatusBadGateway, "Bad Gateway", h.config.ProblemDetails)
	}
}

// handleHTTP2Stream handles HTTP/2 bidirectional streaming
func (h *StreamingProxyHandler) handleHTTP2Stream(w http.ResponseWriter, r *http.Request) {
	outReq := h.prepareRequest(r)

	resp, err := h.roundTrip(w, outReq)
	if err != nil {
		h.handleError(w, r, err)
		return
	}
	defer resp.Body.Close()

	if err := h.processResponse(resp); err != nil {
		h.handleError(w, r, err)
		return
	}

	// HTTP/2 specific: copy headers and flush immediately
	h.copyHeadersAndTrailerAnnouncement(w, resp)
	w.WriteHeader(resp.StatusCode)

	// Flush headers (if supported)
	rc := http.NewResponseController(w)
	if err := rc.Flush(); err != nil {
		// Transforms and some middleware don't support flushing - this is expected
		slog.Debug("flushing not supported (expected for transforms)", "config_id", h.config.ID)
	}

	// Copy body with immediate flushing
	if err := h.copyBodyWithImmediateFlushing(w, resp.Body, rc); err != nil {
		slog.Error("error copying HTTP/2 stream", "error", err, "config_id", h.config.ID)
		return
	}

	// Copy trailers
	if len(resp.Trailer) > 0 {
		rc.Flush()
		for k, vv := range resp.Trailer {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
	}

	h.recordMetrics(r, resp, true)
}

// handleGRPC handles gRPC requests with immediate flushing
func (h *StreamingProxyHandler) handleGRPC(w http.ResponseWriter, r *http.Request) {
	// gRPC requires HTTP/2 and immediate flushing
	// Similar to handleHTTP2Stream
	h.handleHTTP2Stream(w, r)
}

func (h *StreamingProxyHandler) roundTrip(w http.ResponseWriter, outReq *http.Request) (*http.Response, error) {
	proto := h.getProxyProtocolOrDefault()
	if proto.InterimResponses == nil {
		return h.config.Transport().RoundTrip(outReq)
	}

	trace := &httptrace.ClientTrace{
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			if !h.shouldForwardInterimStatus(code) {
				return nil
			}
			h.forwardInterimResponse(w, code, http.Header(header))
			return nil
		},
	}

	ctx := httptrace.WithClientTrace(outReq.Context(), trace)
	outReq = outReq.Clone(ctx)
	return h.config.Transport().RoundTrip(outReq)
}

// handleWebSocket delegates to existing WebSocket handler
func (h *StreamingProxyHandler) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// WebSocket upgrades need direct access to http.Hijacker
	// Delegate to the action's handler (WebSocketAction)
	if wsHandler := h.config.Handler(); wsHandler != nil {
		wsHandler.ServeHTTP(w, r)
	} else {
		http.Error(w, "WebSocket handler not configured", http.StatusInternalServerError)
	}
}

// copyHeadersAndTrailerAnnouncement copies headers and announces trailers
func (h *StreamingProxyHandler) copyHeadersAndTrailerAnnouncement(w http.ResponseWriter, resp *http.Response) {
	// Copy headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	// Announce trailers
	if len(resp.Trailer) > 0 {
		trailerKeys := make([]string, 0, len(resp.Trailer))
		for k := range resp.Trailer {
			trailerKeys = append(trailerKeys, k)
		}
		w.Header().Add("Trailer", strings.Join(trailerKeys, ", "))
	}
}

// copyBodyWithImmediateFlushing copies body and flushes after each write
func (h *StreamingProxyHandler) copyBodyWithImmediateFlushing(w io.Writer, body io.ReadCloser, rc *http.ResponseController) error {
	buf := make([]byte, 32*1024)

	// Check if flushing is supported (once at the start)
	flushSupported := true
	if err := rc.Flush(); err != nil {
		// Transforms and some middleware don't support flushing
		flushSupported = false
	}

	for {
		nr, er := body.Read(buf)
		if nr > 0 {
			nw, ew := w.Write(buf[0:nr])
			if ew != nil {
				return ew
			}
			if nr != nw {
				return io.ErrShortWrite
			}

			// Flush immediately (only if supported)
			if flushSupported {
				rc.Flush() // Ignore errors after first check
			}
		}

		if er == io.EOF {
			break
		}
		if er != nil {
			return er
		}
	}

	return nil
}

// recordMetrics records request/response metrics
func (h *StreamingProxyHandler) recordMetrics(r *http.Request, resp *http.Response, isStreaming bool) {
	duration := time.Since(requestStartTime(r)).Seconds()
	configID := h.config.ID
	if configID == "" {
		configID = "unknown"
	}

	metric.RequestLatency(configID, r.Method, resp.StatusCode, duration)

	if isStreaming {
		metric.StreamingRequest(configID, r.Method)
	}

	// Record protocol detection
	protocol := h.protocolDetector.Detect(r)
	metric.ProtocolDetection(string(protocol))
}

// addProxyHeaders adds standard X-Forwarded-* headers and X-Real-IP
func (h *StreamingProxyHandler) addProxyHeaders(outReq *http.Request, clientReq *http.Request) {
	// Get proxy headers config (returns DefaultProxyHeaders if nil)
	proxyHeaders := h.getProxyHeadersOrDefault()

	// X-Forwarded-For: chain of client IPs
	xffMode := XFFAppend // default
	if proxyHeaders.XForwardedFor != nil {
		xffMode = proxyHeaders.XForwardedFor.Mode
	}

	clientIP := h.extractClientIP(clientReq)

	switch xffMode {
	case XFFAppend:
		if prior := outReq.Header.Get("X-Forwarded-For"); prior != "" {
			clientIP = prior + ", " + clientIP
		}
		outReq.Header.Set("X-Forwarded-For", clientIP)
	case XFFReplace:
		outReq.Header.Set("X-Forwarded-For", clientIP)
	case XFFOff:
		// Don't send X-Forwarded-For
	}

	// X-Forwarded-Proto: original protocol (http/https)
	xfpMode := XFPSet // default
	if proxyHeaders.XForwardedProto != nil {
		xfpMode = proxyHeaders.XForwardedProto.Mode
	}

	if xfpMode != XFPOff {
		proto := "http"
		if clientReq.TLS != nil {
			proto = "https"
		}

		if xfpMode == XFPSet || outReq.Header.Get("X-Forwarded-Proto") == "" {
			outReq.Header.Set("X-Forwarded-Proto", proto)
		}
		// XFPPreserve mode: keep existing value if present
	}

	// X-Forwarded-Host: original host requested by client
	xfhMode := XFHSet // default
	if proxyHeaders.XForwardedHost != nil {
		xfhMode = proxyHeaders.XForwardedHost.Mode
	}

	if xfhMode != XFHOff && clientReq.Host != "" {
		if xfhMode == XFHSet || outReq.Header.Get("X-Forwarded-Host") == "" {
			outReq.Header.Set("X-Forwarded-Host", clientReq.Host)
		}
	}

	// X-Forwarded-Port: original port
	xfportMode := XFPSet // default
	if proxyHeaders.XForwardedPort != nil {
		xfportMode = proxyHeaders.XForwardedPort.Mode
	}

	if xfportMode != XFPOff {
		port := "80"
		if clientReq.TLS != nil {
			port = "443"
		}
		// Extract port from Host header if present
		if strings.Contains(clientReq.Host, ":") {
			_, p, err := net.SplitHostPort(clientReq.Host)
			if err == nil && p != "" {
				port = p
			}
		}

		if xfportMode == XFPSet || outReq.Header.Get("X-Forwarded-Port") == "" {
			outReq.Header.Set("X-Forwarded-Port", port)
		}
	}

	// X-Real-IP: client's actual IP (not a chain)
	if !proxyHeaders.DisableXRealIP {
		outReq.Header.Set("X-Real-IP", clientIP)
	}
}

// extractClientIP extracts the client IP from the request using trust validator
func (h *StreamingProxyHandler) extractClientIP(r *http.Request) string {
	// Use trust validator to extract the first untrusted IP
	return h.trustValidator.ExtractClientIP(r)
}

// addForwardedHeader adds RFC 7239 Forwarded header if configured
func (h *StreamingProxyHandler) addForwardedHeader(outReq *http.Request, clientReq *http.Request) {
	proxyHeaders := h.getProxyHeadersOrDefault()

	// Check if Forwarded config exists and is enabled
	if proxyHeaders.Forwarded == nil || !proxyHeaders.Forwarded.Enable {
		return
	}

	// Build Forwarded header: Forwarded: for=client;host=original;proto=https
	var parts []string

	// for= (client IP, possibly obfuscated)
	clientIP := h.extractClientIP(clientReq)
	if proxyHeaders.Forwarded.ObfuscateIP {
		// Use identifier instead of real IP for privacy
		clientIP = fmt.Sprintf("_hidden_%x", hashString(clientIP))
	}

	if strings.Contains(clientIP, ":") {
		// IPv6 needs quotes
		parts = append(parts, fmt.Sprintf(`for="[%s]"`, clientIP))
	} else {
		parts = append(parts, fmt.Sprintf("for=%s", clientIP))
	}

	if by := strings.TrimSpace(proxyHeaders.Forwarded.By); by != "" {
		parts = append(parts, formatForwardedNode("by", by))
	}

	// host= (original host)
	if clientReq.Host != "" {
		parts = append(parts, formatForwardedValue("host", clientReq.Host))
	}

	// proto= (original protocol)
	proto := "http"
	if clientReq.TLS != nil {
		proto = "https"
	}
	parts = append(parts, fmt.Sprintf("proto=%s", proto))

	forwarded := strings.Join(parts, ";")

	// Append to existing Forwarded header
	if prior := outReq.Header.Get("Forwarded"); prior != "" {
		forwarded = prior + ", " + forwarded
	}

	outReq.Header.Set("Forwarded", forwarded)

	// Also send X-Forwarded-* headers if include_legacy is true (default)
	if h.shouldIncludeLegacyForwarded(proxyHeaders.Forwarded) {
		h.addProxyHeaders(outReq, clientReq)
	}
}

// addViaHeader adds Via header to track proxy chain
func (h *StreamingProxyHandler) addViaHeader(outReq *http.Request, clientReq *http.Request) {
	proxyHeaders := h.getProxyHeadersOrDefault()

	// Check if Via is disabled
	if proxyHeaders.Via != nil && proxyHeaders.Via.Disable {
		return
	}

	// Via: 1.1 soapbucket/1.0.0 (proxy name with version)
	proxyName := "soapbucket/" + version.Version

	// Use request protocol version
	protoVer := fmt.Sprintf("%d.%d", clientReq.ProtoMajor, clientReq.ProtoMinor)
	via := fmt.Sprintf("%s %s", protoVer, proxyName)

	// Append to existing Via header (if this is a proxy chain)
	if prior := outReq.Header.Get("Via"); prior != "" {
		via = prior + ", " + via
	}

	outReq.Header.Set("Via", via)
}

// addViaHeaderToResponse adds Via header to the response per RFC 7230 Section 5.7.1.
// Proxies MUST send an appropriate Via header in each response that it forwards.
func (h *StreamingProxyHandler) addViaHeaderToResponse(resp *http.Response) {
	proxyHeaders := h.getProxyHeadersOrDefault()

	if proxyHeaders.Via != nil && proxyHeaders.Via.Disable {
		return
	}

	proxyName := "soapbucket/" + version.Version

	protoVer := fmt.Sprintf("%d.%d", resp.ProtoMajor, resp.ProtoMinor)
	via := fmt.Sprintf("%s %s", protoVer, proxyName)

	if prior := resp.Header.Get("Via"); prior != "" {
		via = prior + ", " + via
	}

	resp.Header.Set("Via", via)
}

// addUserAgentHeader adds X-SB-UA header with parsed user-agent details
func (h *StreamingProxyHandler) addUserAgentHeader(outReq *http.Request, clientReq *http.Request) {
	proxyHeaders := h.getProxyHeadersOrDefault()
	if proxyHeaders.UserAgent == nil || !proxyHeaders.UserAgent.Enable {
		return
	}

	rd := reqctx.GetRequestData(clientReq.Context())
	if rd == nil || rd.UserAgent == nil {
		return
	}

	ua := rd.UserAgent
	headerName := "X-SB-UA"
	if proxyHeaders.UserAgent.Header != "" {
		headerName = proxyHeaders.UserAgent.Header
	}

	var parts []string
	if ua.Family != "" {
		parts = append(parts, "family="+ua.Family)
	}
	if ua.Major != "" {
		parts = append(parts, "major="+ua.Major)
	}
	if ua.Minor != "" {
		parts = append(parts, "minor="+ua.Minor)
	}
	if ua.Patch != "" {
		parts = append(parts, "patch="+ua.Patch)
	}
	if ua.OSFamily != "" {
		parts = append(parts, "os_family="+ua.OSFamily)
	}
	if ua.OSMajor != "" {
		parts = append(parts, "os_major="+ua.OSMajor)
	}
	if ua.OSMinor != "" {
		parts = append(parts, "os_minor="+ua.OSMinor)
	}
	if ua.DeviceFamily != "" {
		parts = append(parts, "device_family="+ua.DeviceFamily)
	}
	if ua.DeviceBrand != "" {
		parts = append(parts, "device_brand="+ua.DeviceBrand)
	}
	if ua.DeviceModel != "" {
		parts = append(parts, "device_model="+ua.DeviceModel)
	}

	if len(parts) > 0 {
		outReq.Header.Set(headerName, strings.Join(parts, ";"))
	}
}

// addLocationHeader adds X-SB-Location header with GeoIP location data
func (h *StreamingProxyHandler) addLocationHeader(outReq *http.Request, clientReq *http.Request) {
	proxyHeaders := h.getProxyHeadersOrDefault()
	if proxyHeaders.Location == nil || !proxyHeaders.Location.Enable {
		return
	}

	rd := reqctx.GetRequestData(clientReq.Context())
	if rd == nil || rd.Location == nil {
		return
	}

	loc := rd.Location
	headerName := "X-SB-Location"
	if proxyHeaders.Location.Header != "" {
		headerName = proxyHeaders.Location.Header
	}

	var parts []string
	if loc.Country != "" {
		parts = append(parts, "country="+loc.Country)
	}
	if loc.CountryCode != "" {
		parts = append(parts, "country_code="+loc.CountryCode)
	}
	if loc.Continent != "" {
		parts = append(parts, "continent="+loc.Continent)
	}
	if loc.ContinentCode != "" {
		parts = append(parts, "continent_code="+loc.ContinentCode)
	}
	if loc.ASN != "" {
		parts = append(parts, "asn="+loc.ASN)
	}
	if loc.ASName != "" {
		parts = append(parts, "as_name="+loc.ASName)
	}
	if loc.ASDomain != "" {
		parts = append(parts, "as_domain="+loc.ASDomain)
	}

	if len(parts) > 0 {
		outReq.Header.Set(headerName, strings.Join(parts, ";"))
	}
}

// addSignatureHeader adds X-SB-Signature header with the request fingerprint
func (h *StreamingProxyHandler) addSignatureHeader(outReq *http.Request, clientReq *http.Request) {
	proxyHeaders := h.getProxyHeadersOrDefault()
	if proxyHeaders.Signature == nil || !proxyHeaders.Signature.Enable {
		return
	}

	rd := reqctx.GetRequestData(clientReq.Context())
	if rd == nil || rd.Fingerprint == nil {
		return
	}

	headerName := "X-SB-Signature"
	if proxyHeaders.Signature.Header != "" {
		headerName = proxyHeaders.Signature.Header
	}

	outReq.Header.Set(headerName, rd.Fingerprint.Hash)
}

// removeHopByHopHeaders removes connection-specific headers (RFC 9110 Section 7.6.1).
// MUST read Connection before deleting it so that headers named in Connection are also removed.
func (h *StreamingProxyHandler) removeHopByHopHeaders(header http.Header) {
	// Read Connection header BEFORE deleting anything so we can remove the
	// headers it references (RFC 9110 Section 7.6.1).
	connectionTokens := header.Get("Connection")

	// Standard hop-by-hop headers (RFC 9110 Section 7.6.1, RFC 2616 Section 13.5.1)
	hopByHopHeaders := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}

	for _, h := range hopByHopHeaders {
		header.Del(h)
	}

	// Remove headers listed in the Connection field value
	if connectionTokens != "" {
		for _, token := range strings.Split(connectionTokens, ",") {
			header.Del(strings.TrimSpace(token))
		}
	}

	// Remove additional hop-by-hop headers from config
	proxyHeaders := h.getProxyHeadersOrDefault()
	for _, h := range proxyHeaders.AdditionalHopByHopHeaders {
		header.Del(h)
	}
}

func (h *StreamingProxyHandler) restoreRequiredProtocolHeaders(outReq *http.Request, clientReq *http.Request) {
	if h.protocolDetector.Detect(clientReq) == ProtocolGRPC {
		outReq.Header.Set("TE", "trailers")
	}
}

func (h *StreamingProxyHandler) shouldIncludeLegacyForwarded(cfg *ForwardedHeaderConfig) bool {
	if cfg == nil {
		return defaultIncludeLegacyForwarded
	}
	if cfg.IncludeLegacy == nil {
		return !cfg.DisableLegacy
	}
	return *cfg.IncludeLegacy
}

func (h *StreamingProxyHandler) shouldForwardInterimStatus(code int) bool {
	cfg := h.getProxyProtocolOrDefault()
	if cfg.InterimResponses == nil {
		return false
	}
	switch code {
	case http.StatusContinue:
		return cfg.InterimResponses.Forward100Continue
	case http.StatusEarlyHints:
		return cfg.InterimResponses.Forward103EarlyHints
	default:
		return code >= 100 && code < 200 && cfg.InterimResponses.ForwardOther
	}
}

func (h *StreamingProxyHandler) forwardInterimResponse(w http.ResponseWriter, code int, headers http.Header) {
	for key, values := range headers {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(code)
	rc := http.NewResponseController(w)
	_ = rc.Flush()
}

// getProxyHeadersOrDefault returns proxy headers or defaults
func (h *StreamingProxyHandler) getProxyHeadersOrDefault() *ProxyHeaderConfig {
	if h.config.ProxyHeaders == nil {
		return DefaultProxyHeaders
	}
	return h.config.ProxyHeaders
}

// getProxyProtocolOrDefault returns proxy protocol config or secure defaults
func (h *StreamingProxyHandler) getProxyProtocolOrDefault() *ProxyProtocolConfig {
	if h.config.ProxyProtocol == nil {
		return DefaultProxyProtocol
	}
	return h.config.ProxyProtocol
}

// hashString is a simple helper to hash strings for IP obfuscation
func hashString(s string) uint32 {
	h := uint32(0)
	for _, c := range s {
		h = h*31 + uint32(c)
	}
	return h
}

func formatForwardedNode(name string, value string) string {
	if strings.Contains(value, ":") && !strings.HasPrefix(value, "[") {
		return fmt.Sprintf(`%s="[%s]"`, name, escapeForwardedQuotedString(value))
	}
	return formatForwardedValue(name, value)
}

func formatForwardedValue(name string, value string) string {
	if isForwardedToken(value) {
		return fmt.Sprintf("%s=%s", name, value)
	}
	return fmt.Sprintf(`%s="%s"`, name, escapeForwardedQuotedString(value))
}

func escapeForwardedQuotedString(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return value
}

func isForwardedToken(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", r):
		default:
			return false
		}
	}
	return true
}
