// Package logging handles structured request logging to multiple backends (stdout, ClickHouse, file).
package logging

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// AccessLogConfig configures per-origin access logging.
type AccessLogConfig struct {
	Enabled bool     `json:"enabled" yaml:"enabled"`
	Fields  []string `json:"fields,omitempty" yaml:"fields"` // which fields to include
	Format  string   `json:"format,omitempty" yaml:"format"` // "json" or "combined"
}

// defaultAccessLogFields are included when no explicit field list is provided.
var defaultAccessLogFields = []string{
	"method", "path", "status_code", "bytes", "duration_ms", "origin", "remote_addr",
}

// LogAccess logs a structured access log entry using the request logger.
// The format follows the AccessLogConfig conventions: "json" (default) emits
// structured key-value pairs, "combined" emits a single-line combined log format string.
// If extra is non-nil, its entries are merged into the log output.
func LogAccess(r *http.Request, statusCode int, bytesWritten int64, duration time.Duration, origin string, extra map[string]any) {
	logger := GetRequestLogger()

	durationMs := float64(duration.Microseconds()) / 1000.0

	attrs := []any{
		slog.String(FieldMethod, r.Method),
		slog.String(FieldPath, r.URL.Path),
		slog.Int(FieldStatusCode, statusCode),
		slog.Int64(FieldBytes, bytesWritten),
		slog.Float64(FieldDurationMs, durationMs),
		slog.String(FieldOriginID, origin),
		slog.String(FieldRemoteAddr, r.RemoteAddr),
		slog.String(FieldHost, r.Host),
		slog.String(FieldUserAgent, r.UserAgent()),
	}

	for k, v := range extra {
		attrs = append(attrs, slog.Any(k, v))
	}

	logger.Info("access", attrs...)
}

// LogAccessCombined logs an access entry in combined log format as a single string.
// This is useful for compatibility with tools that parse Apache/Nginx combined logs.
func LogAccessCombined(r *http.Request, statusCode int, bytesWritten int64, duration time.Duration, origin string) {
	logger := GetRequestLogger()

	line := fmt.Sprintf("%s - - [%s] \"%s %s %s\" %d %d \"%s\" \"%s\" origin=%s duration=%.3fms",
		r.RemoteAddr,
		time.Now().UTC().Format("02/Jan/2006:15:04:05 -0700"),
		r.Method,
		r.URL.RequestURI(),
		r.Proto,
		statusCode,
		bytesWritten,
		r.Referer(),
		r.UserAgent(),
		origin,
		float64(duration.Microseconds())/1000.0,
	)

	logger.Info(line)
}

// FilterAccessLogFields returns a filtered set of slog attributes based on the
// configured field list. Fields not in the list are omitted. If fields is empty,
// the default set is used.
func FilterAccessLogFields(r *http.Request, statusCode int, bytesWritten int64, duration time.Duration, origin string, fields []string) []any {
	if len(fields) == 0 {
		fields = defaultAccessLogFields
	}

	allowed := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		allowed[strings.ToLower(f)] = struct{}{}
	}

	durationMs := float64(duration.Microseconds()) / 1000.0

	// Build a superset of all possible fields, then filter
	all := map[string]any{
		"method":      r.Method,
		"path":        r.URL.Path,
		"status_code": statusCode,
		"bytes":       bytesWritten,
		"duration_ms": durationMs,
		"origin":      origin,
		"remote_addr": r.RemoteAddr,
		"host":        r.Host,
		"user_agent":  r.UserAgent(),
		"referer":     r.Referer(),
		"scheme":      r.URL.Scheme,
		"proto":       r.Proto,
	}

	var attrs []any
	for _, f := range fields {
		if v, ok := all[f]; ok {
			attrs = append(attrs, slog.Any(f, v))
		}
	}

	return attrs
}
