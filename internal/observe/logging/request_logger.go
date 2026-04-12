// Package logging handles structured request logging to multiple backends (stdout, ClickHouse, file).
package logging

import (
	"bufio"
	"fmt"
	"github.com/soapbucket/sbproxy/internal/cache/store"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/version"
)

// errHijackerNotSupported is a sentinel error to avoid per-call allocation.
var errHijackerNotSupported = fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")

// fieldPool pre-allocates zap.Field slices to reduce heap allocations.
var fieldPool = sync.Pool{
	New: func() any {
		s := make([]zap.Field, 0, 32)
		return &s
	},
}

// responseWriterPool reuses responseWriter structs to avoid per-request heap allocation.
var responseWriterPool = sync.Pool{
	New: func() any {
		return &responseWriter{}
	},
}

func getResponseWriter(w http.ResponseWriter) *responseWriter {
	rw := responseWriterPool.Get().(*responseWriter)
	rw.ResponseWriter = w
	rw.statusCode = 200
	rw.bytesWritten = 0
	// Keep rw.headers if already allocated - reuse across pool cycles
	if rw.headers != nil {
		clear(rw.headers)
	}
	rw.headerWritten = false
	rw.bodyCapture = rw.bodyCapture[:0]
	rw.bodyMax = 0
	rw.captureHeaders = false
	return rw
}

func putResponseWriter(rw *responseWriter) {
	rw.ResponseWriter = nil
	// Don't nil headers — keep the allocated map for reuse
	responseWriterPool.Put(rw)
}

func getFields() *[]zap.Field {
	p := fieldPool.Get().(*[]zap.Field)
	*p = (*p)[:0]
	return p
}

func putFields(p *[]zap.Field) {
	fieldPool.Put(p)
}

// requestLoggerState holds the middleware state including sampling counter.
type requestLoggerState struct {
	zapLogger     *zap.Logger
	config        *RequestLoggingConfig
	sampleCounter atomic.Int64
}

// shouldLog determines whether to log this request based on sampling config.
func (s *requestLoggerState) shouldLog(statusCode int) bool {
	if statusCode >= 400 {
		return true // Always log errors
	}
	if !s.config.Sampling.Enabled || s.config.Sampling.Rate <= 0 {
		return true
	}
	return s.sampleCounter.Add(1)%int64(s.config.Sampling.Rate) == 0
}

// RequestLoggerMiddlewareZap creates a middleware that logs HTTP requests using native zap.
func RequestLoggerMiddlewareZap(zapLogger *zap.Logger, cfg *RequestLoggingConfig) func(http.Handler) http.Handler {
	state := &requestLoggerState{
		zapLogger: zapLogger,
		config:    cfg,
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			startTime := time.Now()

			rw := getResponseWriter(w)

			// Body capture is off by default. Only enable when explicitly configured
			// via origin settings (e.g., discovery mode or traffic capture).
			if rd := reqctx.GetRequestData(r.Context()); rd != nil && rd.Config != nil {
				cp := reqctx.ConfigParams(rd.Config)
				if isBodyCaptureEnabled(cp) {
					overrideMax := maxBodySizeFromConfig(cp)
					if overrideMax > 0 {
						rw.bodyMax = overrideMax
					}
				}
			}
			rw.captureHeaders = cfg.Fields.Headers || rw.bodyMax > 0

			next.ServeHTTP(rw, r)

			duration := time.Since(startTime)
			responseTime := time.Now()

			// Apply body sampling: only keep bodies for errors or slow requests
			// Clear bodies for successful, fast requests (PII compliance)
			if rw.statusCode < 400 && duration < 1*time.Second {
				rw.bodyCapture = rw.bodyCapture[:0] // Clear captured body
			}

			if !state.shouldLog(rw.statusCode) {
				return
			}

			requestData := reqctx.GetRequestData(r.Context())

			fieldsPtr := getFields()
			*fieldsPtr = buildZapRequestLogFields(r, rw, duration, requestData, startTime, responseTime, cfg, *fieldsPtr)

			// Slow request detection
			if cfg.SlowRequestThreshold > 0 && duration > cfg.SlowRequestThreshold {
				zapLogger.Warn("slow request detected", *fieldsPtr...)
			} else {
				zapLogger.Info("request processed", *fieldsPtr...)
			}

			putFields(fieldsPtr)
			putResponseWriter(rw)
		})
	}
}

// RequestLoggerMiddleware creates a middleware using the global zap request logger.
// This is the backward-compatible entry point used in the middleware chain.
func RequestLoggerMiddleware(next http.Handler) http.Handler {
	zapLogger := GetZapRequestLogger()
	if zapLogger == nil {
		// Fallback: use slog-based logging if zap not initialized
		return requestLoggerMiddlewareSlog(next)
	}

	cfg := DefaultRequestLoggingConfig()
	mw := RequestLoggerMiddlewareZap(zapLogger, &cfg)
	return mw(next)
}

// requestLoggerMiddlewareSlog is the fallback slog-based request logger.
func requestLoggerMiddlewareSlog(next http.Handler) http.Handler {
	logger := GetRequestLogger()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		rw := getResponseWriter(w)
		next.ServeHTTP(rw, r)
		duration := time.Since(startTime)
		requestData := reqctx.GetRequestData(r.Context())
		attrs := buildRequestLogAttrs(r, rw, duration, requestData, startTime, time.Now())
		logger.Info("request processed", attrs...)
		putResponseWriter(rw)
	})
}

// maxBodyCaptureSize is the default limit for captured request/response bodies.
const maxBodyCaptureSize = 512 * 1024 // 512KB

// responseWriter wraps http.ResponseWriter to capture status, bytes, and headers.
type responseWriter struct {
	http.ResponseWriter
	statusCode     int
	bytesWritten   int64
	headers        http.Header
	headerWritten  bool
	captureHeaders bool
	// Body capture fields (only used when body capture is enabled)
	bodyCapture []byte
	bodyMax     int
}

// WriteHeader performs the write header operation on the responseWriter.
func (rw *responseWriter) WriteHeader(code int) {
	if !rw.headerWritten {
		rw.statusCode = code
		if rw.captureHeaders {
			if rw.headers == nil {
				rw.headers = make(http.Header, len(rw.ResponseWriter.Header()))
			}
			for k, v := range rw.ResponseWriter.Header() {
				rw.headers[k] = v
			}
		}
		rw.headerWritten = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

// Write performs the write operation on the responseWriter.
func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.headerWritten {
		rw.WriteHeader(200)
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += int64(n)
	// Capture response body if enabled and under limit
	if rw.bodyMax > 0 && len(rw.bodyCapture) < rw.bodyMax {
		if rw.bodyCapture == nil {
			rw.bodyCapture = make([]byte, 0, min(rw.bodyMax, 512))
		}
		remaining := rw.bodyMax - len(rw.bodyCapture)
		if n <= remaining {
			rw.bodyCapture = append(rw.bodyCapture, b[:n]...)
		} else {
			rw.bodyCapture = append(rw.bodyCapture, b[:remaining]...)
		}
	}
	return n, err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Header performs the header operation on the responseWriter.
func (rw *responseWriter) Header() http.Header {
	return rw.ResponseWriter.Header()
}

// Flush performs the flush operation on the responseWriter.
func (rw *responseWriter) Flush() {
	if flusher, ok := rw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Hijack performs the hijack operation on the responseWriter.
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, errHijackerNotSupported
}

// buildZapRequestLogFields builds native zap fields for request logging.
func buildZapRequestLogFields(r *http.Request, rw *responseWriter, duration time.Duration, requestData *reqctx.RequestData, requestTime, responseTime time.Time, cfg *RequestLoggingConfig, fields []zap.Field) []zap.Field {

	// Timestamps
	if cfg.Fields.Timestamps {
		fields = append(fields,
			zap.String("request_timestamp", requestTime.UTC().Format("2006-01-02T15:04:05.000000Z")),
			zap.String("response_timestamp", responseTime.UTC().Format("2006-01-02T15:04:05.000000Z")),
		)
	}

	// Request ID
	if requestData != nil {
		fields = append(fields, zap.String("request_id", requestData.ID))
		fields = append(fields, zap.Int("request_depth", requestData.Depth))
	}

	// Base request fields (always included)
	remoteAddr := r.RemoteAddr
	if mode := ipMaskMode(cfg); mode != "" && mode != "none" {
		if host, port, err := net.SplitHostPort(remoteAddr); err == nil {
			remoteAddr = net.JoinHostPort(maskIP(host, mode), port)
		} else {
			remoteAddr = maskIP(remoteAddr, mode)
		}
	}
	fields = append(fields,
		zap.String("request_method", r.Method),
		zap.String("request_path", r.URL.Path),
		zap.String("request_host", r.Host),
		zap.String("request_remote_addr", remoteAddr),
		zap.String("request_user_agent", r.UserAgent()),
	)

	// Full URL — use string builder from pool to avoid concatenation allocations
	if r.URL != nil {
		urlStr := r.URL.String()
		var fullURL string
		if r.URL.Scheme == "" {
			sb := cacher.GetBuilderWithSize(len(r.Host) + len(urlStr) + 8)
			if r.TLS != nil {
				sb.WriteString("https://")
			} else {
				sb.WriteString("http://")
			}
			sb.WriteString(r.Host)
			sb.WriteString(urlStr)
			fullURL = sb.String()
			cacher.PutBuilder(sb)
		} else {
			fullURL = urlStr
		}
		fields = append(fields, zap.String("request_url", fullURL))

		if cfg.Fields.QueryString && r.URL.RawQuery != "" {
			fields = append(fields, zap.String("request_query", r.URL.RawQuery))
		}
	}

	// Protocol
	fields = append(fields, zap.String("request_protocol", r.Proto))

	if r.ContentLength > 0 {
		fields = append(fields, zap.Int64("request_content_length", r.ContentLength))
	}

	// Headers (optional)
	if cfg.Fields.Headers {
		if ct := r.Header.Get("Content-Type"); ct != "" {
			fields = append(fields, zap.String("request_content_type", ct))
		}
		if accept := r.Header.Get("Accept"); accept != "" {
			fields = append(fields, zap.String("request_accept", accept))
		}
		if ae := r.Header.Get("Accept-Encoding"); ae != "" {
			fields = append(fields, zap.String("request_accept_encoding", ae))
		}
		if al := r.Header.Get("Accept-Language"); al != "" {
			fields = append(fields, zap.String("request_accept_language", al))
		}
		if ref := r.Header.Get("Referer"); ref != "" {
			fields = append(fields, zap.String("request_referer", ref))
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			fields = append(fields, zap.String("request_origin", origin))
		}
	}

	// Forwarded headers (optional)
	if cfg.Fields.ForwardedHeaders {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			fields = append(fields, zap.String("request_x_forwarded_for", xff))
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			fields = append(fields, zap.String("request_x_real_ip", xri))
		}
		if xfp := r.Header.Get("X-Forwarded-Proto"); xfp != "" {
			fields = append(fields, zap.String("request_x_forwarded_proto", xfp))
		}
	}

	// Scheme
	if r.TLS != nil {
		fields = append(fields, zap.String("request_scheme", "https"))
	} else {
		fields = append(fields, zap.String("request_scheme", "http"))
	}

	// Cookies (optional — parse once)
	if cfg.Fields.Cookies {
		cookies := r.Cookies()
		if len(cookies) > 0 {
			fields = append(fields, zap.Int("request_cookie_count", len(cookies)))
		}
	}

	// Auth info (optional)
	if cfg.Fields.AuthInfo {
		if r.Header.Get("Authorization") != "" {
			fields = append(fields, zap.Bool("request_has_authorization", true))
		}
	}

	// Response fields
	fields = append(fields,
		zap.Int("response_status_code", rw.statusCode),
		zap.Int64("response_bytes", rw.bytesWritten),
		zap.Float64("response_duration_ms", float64(duration.Microseconds())/1000.0),
	)

	// Response headers
	if cfg.Fields.Headers && rw.headers != nil {
		if ct := rw.headers.Get("Content-Type"); ct != "" {
			fields = append(fields, zap.String("response_content_type", ct))
		}
		if ce := rw.headers.Get("Content-Encoding"); ce != "" {
			fields = append(fields, zap.String("response_content_encoding", ce))
		}
		if cc := rw.headers.Get("Cache-Control"); cc != "" {
			fields = append(fields, zap.String("response_cache_control", cc))
		}
	}

	// Origin fields from RequestData.Config
	if requestData != nil && requestData.Config != nil {
		configParams := reqctx.ConfigParams(requestData.Config)
		fields = append(fields,
			zap.String("config_id", configParams.GetConfigID()),
			zap.String("workspace_id", configParams.GetWorkspaceID()),
			zap.String("config_version", configParams.GetVersion()),
			zap.String("config_hostname", configParams.GetConfigHostname()),
		)
		if parentID := configParams.GetParentConfigID(); parentID != "" {
			fields = append(fields,
				zap.String("parent_config_id", parentID),
				zap.String("parent_config_hostname", configParams.GetParentConfigHostname()),
			)
		}
		if env := configParams.GetEnvironment(); env != "" {
			fields = append(fields, zap.String("environment", env))
		}
		if tags := configParams.GetTags(); len(tags) > 0 {
			fields = append(fields, zap.Strings("tags", tags))
		}
	}

	// Error fields from policy violations
	if requestData != nil && requestData.Error != "" {
		fields = append(fields, zap.String("error", requestData.Error))
		if requestData.ErrorType != "" {
			fields = append(fields, zap.String("error_type", requestData.ErrorType))
		}
		if requestData.ErrorCode != "" {
			fields = append(fields, zap.String("error_code", requestData.ErrorCode))
		}
	}

	// Proxy version (always included for diagnostics)
	fields = append(fields, zap.String("proxy_version", version.String()))

	// Auth data (optional)
	if cfg.Fields.AuthInfo && requestData != nil && requestData.SessionData != nil && requestData.SessionData.AuthData != nil {
		authData := requestData.SessionData.AuthData
		if authData.Data != nil {
			fields = append(fields, zap.Bool("auth_data_present", true))
			if userID, ok := authData.Data["user_id"].(string); ok && userID != "" {
				fields = append(fields, zap.String("user_id", userID))
			}
		}
	}

	// Session
	if requestData != nil && requestData.SessionData != nil && requestData.SessionData.ID != "" {
		fields = append(fields, zap.String("session_id", requestData.SessionData.ID))
	}

	// App version (optional)
	if cfg.Fields.AppVersion {
		fields = append(fields,
			zap.String("app_version", version.String()),
			zap.String("build_hash", version.BuildHash),
			zap.String("app_env", version.AppEnv),
		)
	}

	// Source IP (optional)
	if cfg.Fields.Location && r.RemoteAddr != "" {
		var sourceIP string
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			sourceIP = host
		} else {
			sourceIP = r.RemoteAddr
		}
		if mode := ipMaskMode(cfg); mode != "" && mode != "none" {
			sourceIP = maskIP(sourceIP, mode)
		}
		fields = append(fields, zap.String("source_ip", sourceIP))
	}

	// Fingerprint (optional)
	if cfg.Fields.Fingerprint && requestData != nil && requestData.Fingerprint != nil {
		fp := requestData.Fingerprint
		if fp.Hash != "" {
			fields = append(fields, zap.String("fingerprint", fp.Hash))
		}
		if fp.Composite != "" {
			fields = append(fields, zap.String("fingerprint_composite", fp.Composite))
		}
		if fp.CookieCount > 0 {
			fields = append(fields, zap.Int("fingerprint_cookie_count", fp.CookieCount))
		}
		if fp.Version != "" {
			fields = append(fields, zap.String("fingerprint_version", fp.Version))
		}
	}

	// Original request (optional)
	if cfg.Fields.OriginalRequest && requestData != nil && requestData.OriginalRequest != nil {
		orig := requestData.OriginalRequest
		if orig.Method != "" && orig.Method != r.Method {
			fields = append(fields, zap.String("original_request_method", orig.Method))
		}
		if orig.Path != "" && orig.Path != r.URL.Path {
			fields = append(fields, zap.String("original_request_path", orig.Path))
		}
		if len(orig.Body) > 0 {
			fields = append(fields, zap.Int("original_request_body_size", len(orig.Body)))
		}
	}

	// Cache fields (optional)
	if cfg.Fields.CacheInfo && requestData != nil {
		if requestData.ResponseCacheHit && requestData.ResponseCacheKey != "" {
			fields = append(fields,
				zap.Bool("response_cache_hit", true),
				zap.String("response_cache_key", requestData.ResponseCacheKey),
			)
		}
		if requestData.SignatureCacheHit && requestData.SignatureCacheKey != "" {
			fields = append(fields,
				zap.Bool("signature_cache_hit", true),
				zap.String("signature_cache_key", requestData.SignatureCacheKey),
			)
		}
	}

	// Body capture fields (when body capture is enabled)
	if rw.bodyMax > 0 {
		// Indicate if body capture was attempted
		if len(rw.bodyCapture) > 0 || (requestData != nil && requestData.OriginalRequest != nil && len(requestData.OriginalRequest.Body) > 0) {
			fields = append(fields, zap.Bool("body_captured", true))
		}

		// Track if body was truncated (indicates original was larger than capture limit)
		bodyTruncated := len(rw.bodyCapture) >= rw.bodyMax ||
			(requestData != nil && requestData.OriginalRequest != nil && len(requestData.OriginalRequest.Body) > maxBodyCaptureSize)
		if bodyTruncated {
			fields = append(fields, zap.Bool("body_truncated", true))
		}

		// Only include bodies if they were captured (not cleared by sampling logic)
		if len(rw.bodyCapture) > 0 {
			fields = append(fields, zap.String("response_body", string(rw.bodyCapture)))
		}

		// Request body from OriginalRequest
		if requestData != nil && requestData.OriginalRequest != nil && len(requestData.OriginalRequest.Body) > 0 {
			body := requestData.OriginalRequest.Body
			if len(body) > maxBodyCaptureSize {
				body = body[:maxBodyCaptureSize]
			}
			fields = append(fields, zap.String("request_body", string(body)))
		}

		// Full request headers
		if r != nil {
			reqHeaders := make(map[string]string, len(r.Header))
			for k, v := range r.Header {
				if len(v) > 0 {
					reqHeaders[k] = v[0]
				}
			}
			fields = append(fields, zap.Any("request_headers_full", reqHeaders))
		}

		// Full response headers
		if rw.headers != nil {
			respHeaders := make(map[string]string, len(rw.headers))
			for k, v := range rw.headers {
				if len(v) > 0 {
					respHeaders[k] = v[0]
				}
			}
			fields = append(fields, zap.Any("response_headers_full", respHeaders))
		}
	}

	// AI usage fields (always included when present)
	if requestData != nil && requestData.AIUsage != nil {
		ai := requestData.AIUsage
		fields = append(fields,
			zap.String("ai_provider", ai.Provider),
			zap.String("ai_model", ai.Model),
			zap.Int("ai_input_tokens", ai.InputTokens),
			zap.Int("ai_output_tokens", ai.OutputTokens),
			zap.Int("ai_total_tokens", ai.TotalTokens),
			zap.Int("ai_cached_tokens", ai.CachedTokens),
			zap.Float64("ai_cost_usd", ai.CostUSD),
			zap.String("ai_routing_strategy", ai.RoutingStrategy),
			zap.Bool("ai_streaming", ai.Streaming),
		)
		if ai.Agent != "" {
			fields = append(fields, zap.String("ai_agent", ai.Agent))
		}
		if ai.SessionID != "" {
			fields = append(fields, zap.String("ai_session_id", ai.SessionID))
		}
		if ai.APIKeyName != "" {
			fields = append(fields, zap.String("ai_api_key_name", ai.APIKeyName))
		}
		if ai.CacheHit {
			fields = append(fields, zap.Bool("ai_cached", true))
			if ai.CacheType != "" {
				fields = append(fields, zap.String("ai_cache_type", ai.CacheType))
			}
		}
		if ai.ModelDowngraded {
			fields = append(fields,
				zap.Bool("ai_model_downgraded", true),
				zap.String("ai_original_model", ai.OriginalModel),
			)
		}
		if ai.PromptID != "" {
			fields = append(fields, zap.String("ai_prompt_id", ai.PromptID))
		}
		if ai.PromptEnvironment != "" {
			fields = append(fields, zap.String("ai_prompt_environment", ai.PromptEnvironment))
		}
		if ai.PromptVersion > 0 {
			fields = append(fields, zap.Int("ai_prompt_version", ai.PromptVersion))
		}
		if ai.BudgetScope != "" {
			fields = append(fields, zap.String("ai_budget_scope", ai.BudgetScope))
		}
		if ai.BudgetScopeValue != "" {
			fields = append(fields, zap.String("ai_budget_scope_value", ai.BudgetScopeValue))
		}
		if ai.BudgetUtilization > 0 {
			fields = append(fields, zap.Float64("ai_budget_utilization", ai.BudgetUtilization))
		}
		// Compliance audit fields
		if ai.APIKeyHash != "" {
			fields = append(fields, zap.String("ai_api_key_hash", ai.APIKeyHash))
		}
		if ai.PromptHash != "" {
			fields = append(fields, zap.String("ai_prompt_hash", ai.PromptHash))
		}
		if ai.ResponseHash != "" {
			fields = append(fields, zap.String("ai_response_hash", ai.ResponseHash))
		}
		if len(ai.Tags) > 0 {
			fields = append(fields, zap.Any("ai_tags", ai.Tags))
		}
		// Governance reporting fields
		if ai.StreamingGuardrailMode != "" {
			fields = append(fields, zap.String("ai_streaming_guardrail_mode", ai.StreamingGuardrailMode))
		}
		if len(ai.ProviderExclusions) > 0 {
			fields = append(fields, zap.Any("ai_provider_exclusions", ai.ProviderExclusions))
		}
	}

	return fields
}

// isBodyCaptureEnabled checks if body capture is enabled in the origin config params.
// Looks for observability.enabled or har_capture.enabled in the config.
func isBodyCaptureEnabled(cp reqctx.ConfigParams) bool {
	// Check under observability.enabled (new config format)
	if obs, ok := cp["observability"].(map[string]any); ok {
		// Top-level enabled flag (used by current UI config)
		if enabled, ok := obs["enabled"].(bool); ok && enabled {
			return true
		}
		// Nested har_capture.enabled (schema format)
		switch hc := obs["har_capture"].(type) {
		case bool:
			return hc
		case map[string]any:
			if enabled, ok := hc["enabled"].(bool); ok {
				return enabled
			}
		}
	}
	// Legacy: har_capture at config root
	if harCapture, ok := cp["har_capture"].(map[string]any); ok {
		if enabled, ok := harCapture["enabled"].(bool); ok {
			return enabled
		}
	}
	return false
}

// maxBodySizeFromConfig extracts the max_body_size from observability config.
// Falls back to the default maxBodyCaptureSize if not configured.
func maxBodySizeFromConfig(cp reqctx.ConfigParams) int {
	if obs, ok := cp["observability"].(map[string]any); ok {
		// Check for top-level max_body_size
		for _, key := range []string{"max_body_size"} {
			switch n := obs[key].(type) {
			case float64:
				if n > 0 {
					return int(n)
				}
			case int:
				if n > 0 {
					return n
				}
			}
		}
		// Check nested har_capture.max_body_size
		if hc, ok := obs["har_capture"].(map[string]any); ok {
			if n, ok := hc["max_body_size"].(float64); ok && n > 0 {
				return int(n)
			}
		}
	}
	return maxBodyCaptureSize // 512KB default
}

// buildRequestLogAttrs builds slog attributes for backward-compat slog request logging.
func buildRequestLogAttrs(r *http.Request, rw *responseWriter, duration time.Duration, requestData *reqctx.RequestData, requestTime, responseTime time.Time) []any {
	// Keep minimal slog fallback — just core fields
	var attrs []any

	if requestData != nil {
		attrs = append(attrs, "request_id", requestData.ID)
	}
	attrs = append(attrs,
		"request_method", r.Method,
		"request_path", r.URL.Path,
		"request_host", r.Host,
		"response_status_code", rw.statusCode,
		"response_bytes", rw.bytesWritten,
		"response_duration_ms", float64(duration.Microseconds())/1000.0,
	)

	return attrs
}
