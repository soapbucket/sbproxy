package logging

// This file contains helper functions for building structured log fields.
// Each function appends a category of fields to the slice, keeping
// buildZapRequestLogFields manageable and each category independently testable.

import (
	"net/http"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"go.uber.org/zap"
)

// appendRequestIDFields adds request ID and depth fields.
func appendRequestIDFields(fields []zap.Field, rd *reqctx.RequestData) []zap.Field {
	if rd != nil {
		fields = append(fields,
			zap.String("request_id", rd.ID),
			zap.Int("request_depth", rd.Depth),
		)
	}
	return fields
}

// appendResponseFields adds status code, bytes written, and duration.
func appendResponseFields(fields []zap.Field, rw *responseWriter, durationMs float64) []zap.Field {
	return append(fields,
		zap.Int("response_status_code", rw.statusCode),
		zap.Int64("response_bytes", rw.bytesWritten),
		zap.Float64("response_duration_ms", durationMs),
	)
}

// appendResponseHeaderFields adds response content-type and encoding if configured.
func appendResponseHeaderFields(fields []zap.Field, rw *responseWriter) []zap.Field {
	if rw.headers == nil {
		return fields
	}
	if ct := rw.headers.Get("Content-Type"); ct != "" {
		fields = append(fields, zap.String("response_content_type", ct))
	}
	if ce := rw.headers.Get("Content-Encoding"); ce != "" {
		fields = append(fields, zap.String("response_content_encoding", ce))
	}
	return fields
}

// appendConfigFields adds origin config fields from RequestData.
func appendConfigFields(fields []zap.Field, rd *reqctx.RequestData) []zap.Field {
	if rd == nil || rd.Config == nil {
		return fields
	}
	configData := reqctx.ConfigParams(rd.Config)
	if id := configData.GetConfigID(); id != "" {
		fields = append(fields, zap.String("config_id", id))
	}
	if hostname := configData.GetConfigHostname(); hostname != "" {
		fields = append(fields, zap.String("config_hostname", hostname))
	}
	if wsID := configData.GetWorkspaceID(); wsID != "" {
		fields = append(fields, zap.String("workspace_id", wsID))
	}
	if mode := configData.GetConfigMode(); mode != "" {
		fields = append(fields, zap.String("config_mode", mode))
	}
	if reason := configData.GetConfigReason(); reason != "" {
		fields = append(fields, zap.String("config_reason", reason))
	}
	return fields
}

// appendSourceIPFields adds client IP and related network fields.
func appendSourceIPFields(fields []zap.Field, r *http.Request) []zap.Field {
	if r.RemoteAddr != "" {
		fields = append(fields, zap.String("source_ip", r.RemoteAddr))
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		fields = append(fields, zap.String("x_forwarded_for", xff))
	}
	return fields
}

// appendFingerprintFields adds client fingerprint data if available.
func appendFingerprintFields(fields []zap.Field, rd *reqctx.RequestData) []zap.Field {
	if rd == nil || rd.Fingerprint == nil {
		return fields
	}
	fp := rd.Fingerprint
	if fp.Hash != "" {
		fields = append(fields, zap.String("fingerprint_hash", fp.Hash))
	}
	if fp.TLSHash != "" {
		fields = append(fields, zap.String("fingerprint_tls_hash", fp.TLSHash))
	}
	return fields
}

// appendCacheFields adds cache hit/miss information.
func appendCacheFields(fields []zap.Field, rd *reqctx.RequestData) []zap.Field {
	if rd == nil {
		return fields
	}
	if rd.ResponseCacheKey != "" {
		fields = append(fields, zap.String("response_cache_key", rd.ResponseCacheKey))
	}
	if rd.SignatureCacheKey != "" {
		fields = append(fields, zap.String("signature_cache_key", rd.SignatureCacheKey))
	}
	return fields
}

// appendAIUsageFields adds AI/LLM usage metrics if present.
func appendAIUsageFields(fields []zap.Field, rd *reqctx.RequestData) []zap.Field {
	if rd == nil || rd.AIUsage == nil {
		return fields
	}
	usage := rd.AIUsage
	if usage.Model != "" {
		fields = append(fields, zap.String("ai_model", usage.Model))
	}
	if usage.Provider != "" {
		fields = append(fields, zap.String("ai_provider", usage.Provider))
	}
	if usage.InputTokens > 0 {
		fields = append(fields, zap.Int("ai_input_tokens", usage.InputTokens))
	}
	if usage.OutputTokens > 0 {
		fields = append(fields, zap.Int("ai_output_tokens", usage.OutputTokens))
	}
	if usage.TotalTokens > 0 {
		fields = append(fields, zap.Int("ai_total_tokens", usage.TotalTokens))
	}
	if usage.CostUSD > 0 {
		fields = append(fields, zap.Float64("ai_cost_usd", usage.CostUSD))
	}
	if usage.CacheHit {
		fields = append(fields, zap.Bool("ai_cached", true))
	}
	if usage.Streaming {
		fields = append(fields, zap.Bool("ai_streaming", true))
	}
	return fields
}
