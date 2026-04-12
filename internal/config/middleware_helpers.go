// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/engine/transport"
	"github.com/soapbucket/sbproxy/internal/observe/events"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// ── event_helpers.go ──────────────────────────────────────────────────────────

func emitUpstreamTimeout(ctx context.Context, cfg *Config, r *http.Request, upstreamURL string, timeoutSeconds int) {
	if cfg == nil || !cfg.EventEnabled("upstream.timeout") {
		return
	}
	event := &events.UpstreamTimeout{
		EventBase:      events.NewBase("upstream.timeout", events.SeverityError, cfg.WorkspaceID, reqctx.GetRequestID(ctx)),
		UpstreamURL:    upstreamURL,
		TimeoutSeconds: timeoutSeconds,
		Path:           requestPath(r),
	}
	event.Origin = ConfigOriginContext(cfg)
	events.Emit(ctx, cfg.WorkspaceID, event)
}

func emitUpstream5xx(ctx context.Context, cfg *Config, r *http.Request, upstreamURL string, statusCode int, responseTimeMS int64) {
	if cfg == nil || !cfg.EventEnabled("upstream.5xx") {
		return
	}
	event := &events.Upstream5xx{
		EventBase:      events.NewBase("upstream.5xx", events.SeverityError, cfg.WorkspaceID, reqctx.GetRequestID(ctx)),
		UpstreamURL:    upstreamURL,
		StatusCode:     statusCode,
		Path:           requestPath(r),
		ResponseTimeMS: responseTimeMS,
	}
	event.Origin = ConfigOriginContext(cfg)
	events.Emit(ctx, cfg.WorkspaceID, event)
}

// ConfigOriginContext builds an events.OriginContext from a Config.
func ConfigOriginContext(cfg *Config) events.OriginContext {
	if cfg == nil {
		return events.OriginContext{}
	}
	actionType := ""
	if cfg.action != nil {
		actionType = cfg.action.GetType()
	}
	return events.OriginContext{
		OriginID:    cfg.ID,
		OriginName:  cfg.OriginName,
		Hostname:    cfg.Hostname,
		VersionID:   cfg.Version,
		WorkspaceID: cfg.WorkspaceID,
		ActionType:  actionType,
		Environment: cfg.Environment,
		Tags:        cfg.Tags,
	}
}

func requestPath(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	return r.URL.Path
}

// ── csp_report.go ─────────────────────────────────────────────────────────────

// truncateString truncates a string to maxLen characters for logging.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// CSPViolationReportHandler handles CSP violation reports from browsers.
type CSPViolationReportHandler struct {
	config *Config
}

// NewCSPViolationReportHandler creates a new CSP violation report handler.
func NewCSPViolationReportHandler(config *Config) *CSPViolationReportHandler {
	return &CSPViolationReportHandler{
		config: config,
	}
}

// ServeHTTP handles CSP violation reports.
func (h *CSPViolationReportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Parse the violation report
	var report CSPViolationReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		configID := "unknown"
		if h.config != nil {
			configID = h.config.ID
		}
		slog.Warn("failed to parse CSP violation report",
			"error", err,
			"config_id", configID,
			"content_type", r.Header.Get("Content-Type"),
			"content_length", r.ContentLength)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Log the violation report with comprehensive details
	configID := "unknown"
	if h.config != nil {
		configID = h.config.ID
	}

	slog.Warn("CSP violation detected",
		"config_id", configID,
		"document_uri", report.Body.DocumentURI,
		"referrer", report.Body.Referrer,
		"violated_directive", report.Body.ViolatedDirective,
		"effective_directive", report.Body.EffectiveDirective,
		"blocked_uri", report.Body.BlockedURI,
		"source_file", report.Body.SourceFile,
		"line_number", report.Body.LineNumber,
		"column_number", report.Body.ColumnNumber,
		"script_sample", truncateString(report.Body.ScriptSample, 100),
		"original_policy", truncateString(report.Body.OriginalPolicy, 200),
		"disposition", report.Body.Disposition,
		"status_code", report.Body.StatusCode,
	)

	// Log at debug level with full details for troubleshooting
	slog.Debug("CSP violation report details",
		"config_id", configID,
		"full_report", report,
	)

	// Return 204 No Content as per CSP spec
	w.WriteHeader(http.StatusNoContent)
}

// HandleCSPViolationReport is a convenience function to handle CSP violation reports
// when config is not available.
func HandleCSPViolationReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		slog.Debug("CSP violation report rejected (wrong method)",
			"method", r.Method,
			"path", r.URL.Path)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var report CSPViolationReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		slog.Warn("failed to parse CSP violation report",
			"error", err,
			"path", r.URL.Path)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	slog.Warn("CSP violation detected (fallback handler)",
		"document_uri", report.Body.DocumentURI,
		"violated_directive", report.Body.ViolatedDirective,
		"effective_directive", report.Body.EffectiveDirective,
		"blocked_uri", report.Body.BlockedURI,
		"source_file", report.Body.SourceFile,
		"line_number", report.Body.LineNumber,
		"column_number", report.Body.ColumnNumber,
	)

	w.WriteHeader(http.StatusNoContent)
}

// ── cookie_jar.go ─────────────────────────────────────────────────────────────

// SetupCookieJar configures cookie jar support for this config.
// This should be called after config is loaded to avoid import cycles.
func (c *Config) SetupCookieJar(cookieJarFn CookieJarFn) {
	if cookieJarFn == nil {
		return
	}

	c.CookieJarFn = cookieJarFn

	// Wrap action transport with cookie jar transport if action is a proxy
	if c.action != nil && c.action.IsProxy() {
		c.wrapActionTransportWithCookieJar()
	}

	slog.Info("session cookie jar configured",
		"config_id", c.ID,
		"hostname", c.Hostname)
}

// wrapActionTransportWithCookieJar wraps the action's transport with cookie jar support.
func (c *Config) wrapActionTransportWithCookieJar() {
	if c.action == nil || c.CookieJarFn == nil {
		return
	}

	// Get the current transport function
	baseTrFn := c.action.Transport()
	if baseTrFn == nil {
		return
	}

	// Wrap the base transport with cookie jar transport
	wrappedTr := transport.NewCookieJarTransport(baseTrFn, c.CookieJarFn)

	// Convert wrapped transport back to TransportFn
	wrappedTrFn := TransportFn(wrappedTr.RoundTrip)

	// Try to set the transport on actions that support it
	if baseAction, ok := c.action.(interface{ setTransport(http.RoundTripper) }); ok {
		baseAction.setTransport(wrappedTrFn)
	} else {
		// For actions that don't support direct transport setting,
		// store the wrapped transport for later use
		c.cookieJarTransport = wrappedTrFn
		slog.Debug("stored wrapped transport at config level",
			"action_type", c.action.GetType(),
			"config_id", c.ID)
	}
}
