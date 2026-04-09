// Package logging handles structured request logging to multiple backends (stdout, ClickHouse, file).
package logging

import (
	"log/slog"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// Standard field names for consistent logging across the application
// These constants ensure that all logs use the same field names for the same data

// Request-related fields
const (
	// FieldRequestID is a constant for field request id.
	FieldRequestID     = "request_id"
	// FieldMethod is a constant for field method.
	FieldMethod        = "method"
	// FieldPath is a constant for field path.
	FieldPath          = "path"
	// FieldHost is a constant for field host.
	FieldHost          = "host"
	// FieldRemoteAddr is a constant for field remote addr.
	FieldRemoteAddr    = "remote_addr"
	// FieldUserAgent is a constant for field user agent.
	FieldUserAgent     = "user_agent"
	// FieldContentLength is a constant for field content length.
	FieldContentLength = "content_length"
	// FieldContentType is a constant for field content type.
	FieldContentType   = "content_type"
	// FieldReferer is a constant for field referer.
	FieldReferer       = "referer"
	// FieldScheme is a constant for field scheme.
	FieldScheme        = "scheme"
)

// Response-related fields
const (
	// FieldStatusCode is a constant for field status code.
	FieldStatusCode = "status_code"
	// FieldDurationMs is a constant for field duration ms.
	FieldDurationMs = "duration_ms"
	// FieldBytes is a constant for field bytes.
	FieldBytes      = "bytes"
)

// User-related fields
const (
	// FieldUserID is a constant for field user id.
	FieldUserID = "user_id"
	// FieldEmail is a constant for field email.
	FieldEmail  = "email"
	// FieldRoles is a constant for field roles.
	FieldRoles  = "roles"
)

// Origin-related fields
const (
	// FieldOriginID is a constant for field origin id.
	FieldOriginID       = "origin_id"
	// FieldOriginHostname is a constant for field origin hostname.
	FieldOriginHostname = "hostname"
	// FieldOriginType is a constant for field origin type.
	FieldOriginType     = "type"
	// FieldWorkspaceID is a constant for field workspace id.
	FieldWorkspaceID    = "workspace_id"
	// FieldConfigID is a constant for field config id.
	FieldConfigID       = "config_id"
	// FieldVersion is a constant for field version.
	FieldVersion        = "version"
)

// Session-related fields
const (
	// FieldSessionID is a constant for field session id.
	FieldSessionID = "session_id"
)

// Error-related fields
const (
	// FieldError is a constant for field error.
	FieldError      = "error"
	// FieldErrorType is a constant for field error type.
	FieldErrorType  = "error_type"
	// FieldErrorCode is a constant for field error code.
	FieldErrorCode  = "error_code"
	// FieldStackTrace is a constant for field stack trace.
	FieldStackTrace = "stack_trace"
)

// Tracing-related fields (grouped)
const (
	// FieldTracingGroup is a constant for field tracing group.
	FieldTracingGroup = "tracing"
	// FieldTraceID is a constant for field trace id.
	FieldTraceID      = "trace_id"
	// FieldSpanID is a constant for field span id.
	FieldSpanID       = "span_id"
	// FieldParentSpanID is a constant for field parent span id.
	FieldParentSpanID = "parent_span_id"
)

// Location-related fields
const (
	// FieldCountry is a constant for field country.
	FieldCountry     = "country"
	// FieldCountryCode is a constant for field country code.
	FieldCountryCode = "country_code"
	// FieldASN is a constant for field asn.
	FieldASN         = "asn"
	// FieldASName is a constant for field as name.
	FieldASName      = "as_name"
	// FieldSourceIP is a constant for field source ip.
	FieldSourceIP    = "source_ip"
)

// Security-related fields
const (
	// FieldSecurityEventType is a constant for field security event type.
	FieldSecurityEventType = "event_type"
	// FieldSeverity is a constant for field severity.
	FieldSeverity          = "severity"
	// FieldAction is a constant for field action.
	FieldAction            = "action"
	// FieldResource is a constant for field resource.
	FieldResource          = "resource"
	// FieldResult is a constant for field result.
	FieldResult            = "result"
)

// Caller information
const (
	// FieldCaller is a constant for field caller.
	FieldCaller = "caller"
)

// Helper functions to create standardized log attributes

// RequestAttrs creates standard request attributes
func RequestAttrs(r *http.Request, requestID string) []any {
	return []any{
		slog.Group("request",
			slog.String(FieldRequestID, requestID),
			slog.String(FieldMethod, r.Method),
			slog.String(FieldPath, r.URL.Path),
			slog.String(FieldHost, r.Host),
			slog.String(FieldRemoteAddr, r.RemoteAddr),
			slog.String(FieldUserAgent, r.UserAgent()),
			slog.Int64(FieldContentLength, r.ContentLength),
		),
	}
}

// ResponseAttrs creates standard response attributes
func ResponseAttrs(statusCode int, bytes int64, duration time.Duration) []any {
	return []any{
		slog.Group("response",
			slog.Int(FieldStatusCode, statusCode),
			slog.Int64(FieldBytes, bytes),
			slog.Float64(FieldDurationMs, float64(duration.Microseconds())/1000.0),
		),
	}
}

// UserAttrs creates standard user attributes
func UserAttrs(userID, email string, roles []string) []any {
	return []any{
		slog.Group("user",
			slog.String(FieldUserID, userID),
			slog.String(FieldEmail, email),
			slog.Any(FieldRoles, roles),
		),
	}
}

// OriginAttrs creates standard origin attributes
func OriginAttrs(originID, hostname, originType, workspaceID, configID, version string) []any {
	attrs := []any{
			slog.String(FieldOriginID, originID),
			slog.String(FieldOriginHostname, hostname),
			slog.String(FieldOriginType, originType),
	}
	
	// Add workspace_id if provided
	if workspaceID != "" {
		attrs = append(attrs, slog.String(FieldWorkspaceID, workspaceID))
	}
	
	// Add config_id if provided (may be same as origin_id, but kept separate for clarity)
	if configID != "" {
		attrs = append(attrs, slog.String(FieldConfigID, configID))
	}
	
	// Add version (should not be empty per user requirement)
	if version != "" {
		attrs = append(attrs, slog.String(FieldVersion, version))
	}
	
	return []any{
		slog.Group("origin", attrs...),
	}
}

// SessionAttrs creates standard session attributes
func SessionAttrs(sessionID string) []any {
	return []any{
		slog.Group("session",
			slog.String(FieldSessionID, sessionID),
		),
	}
}

// ErrorAttrs creates standard error attributes
func ErrorAttrs(err error, errorType, errorCode string) []any {
	attrs := []any{
		slog.Group("error",
			slog.String(FieldError, err.Error()),
		),
	}

	if errorType != "" {
		attrs = append(attrs, slog.String(FieldErrorType, errorType))
	}
	if errorCode != "" {
		attrs = append(attrs, slog.String(FieldErrorCode, errorCode))
	}

	return attrs
}

// LocationAttrs creates standard location attributes
func LocationAttrs(country, countryCode, asn, asName, sourceIP string) []any {
	attrs := []any{}

	if sourceIP != "" {
		attrs = append(attrs, slog.String(FieldSourceIP, sourceIP))
	}
	if country != "" {
		attrs = append(attrs, slog.String(FieldCountry, country))
	}
	if countryCode != "" {
		attrs = append(attrs, slog.String(FieldCountryCode, countryCode))
	}
	if asn != "" {
		attrs = append(attrs, slog.String(FieldASN, asn))
	}
	if asName != "" {
		attrs = append(attrs, slog.String(FieldASName, asName))
	}

	return attrs
}

// --- zap field helpers ---

// ZapRequestFields creates standard zap request fields.
func ZapRequestFields(r *http.Request, requestID string) []zap.Field {
	return []zap.Field{
		zap.String(FieldRequestID, requestID),
		zap.String(FieldMethod, r.Method),
		zap.String(FieldPath, r.URL.Path),
		zap.String(FieldHost, r.Host),
		zap.String(FieldRemoteAddr, r.RemoteAddr),
		zap.String(FieldUserAgent, r.UserAgent()),
		zap.Int64(FieldContentLength, r.ContentLength),
	}
}

// ZapResponseFields creates standard zap response fields.
func ZapResponseFields(statusCode int, bytes int64, duration time.Duration) []zap.Field {
	return []zap.Field{
		zap.Int(FieldStatusCode, statusCode),
		zap.Int64(FieldBytes, bytes),
		zap.Float64(FieldDurationMs, float64(duration.Microseconds())/1000.0),
	}
}

// ZapErrorCategoryFields creates zap fields for error categorization.
func ZapErrorCategoryFields(category, source string) []zap.Field {
	return []zap.Field{
		zap.String(FieldErrorCategory, category),
		zap.String(FieldErrorSource, source),
	}
}
