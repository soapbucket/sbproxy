// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// truncateString truncates a string to maxLen characters for logging
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// CSPViolationReportHandler handles CSP violation reports from browsers
type CSPViolationReportHandler struct {
	config *Config
}

// NewCSPViolationReportHandler creates a new CSP violation report handler
func NewCSPViolationReportHandler(config *Config) *CSPViolationReportHandler {
	return &CSPViolationReportHandler{
		config: config,
	}
}

// ServeHTTP handles CSP violation reports
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

	// TODO: In the future, you could:
	// - Store violations in a database
	// - Send to external monitoring service
	// - Aggregate violations for analysis
	// - Auto-generate CSP policies based on violations

	// Return 204 No Content as per CSP spec
	w.WriteHeader(http.StatusNoContent)
}

// HandleCSPViolationReport is a convenience function to handle CSP violation reports
func HandleCSPViolationReport(w http.ResponseWriter, r *http.Request) {
	// This is a fallback handler that can be used when config is not available
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

