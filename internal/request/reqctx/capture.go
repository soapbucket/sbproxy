// Package models defines shared data types, constants, and request/response models used across packages.
package reqctx

import (
	"net/http"
	"time"
)

// Exchange represents a captured HTTP request/response pair in a HAR-compatible format.
// It is the core data structure for the traffic capture system (Phase 1).
type Exchange struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	Duration  int64             `json:"duration"` // Microseconds
	Request   CapturedRequest   `json:"request"`
	Response  CapturedResponse  `json:"response"`
	Meta      map[string]string `json:"meta,omitempty"` // Captured CEL variables, policy decisions
}

// CapturedRequest represents a captured HTTP request.
type CapturedRequest struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	Path        string      `json:"path"`
	Host        string      `json:"host"`
	Scheme      string      `json:"scheme"`
	Protocol    string      `json:"protocol"`
	Headers     http.Header `json:"headers"`
	Body        []byte      `json:"body,omitempty"`
	BodySize    int64       `json:"body_size"`
	Truncated   bool        `json:"truncated,omitempty"`
	ContentType string      `json:"content_type,omitempty"`
	RemoteAddr  string      `json:"remote_addr"`
}

// CapturedResponse represents a captured HTTP response.
type CapturedResponse struct {
	StatusCode  int         `json:"status_code"`
	Headers     http.Header `json:"headers"`
	Body        []byte      `json:"body,omitempty"`
	BodySize    int64       `json:"body_size"`
	Truncated   bool        `json:"truncated,omitempty"`
	ContentType string      `json:"content_type,omitempty"`
}

// TrafficCaptureConfig represents the per-site traffic capture configuration.
// This is a behavioral configuration — all infrastructure (messenger, cacher) is global.
type TrafficCaptureConfig struct {
	Enabled     bool    `json:"enabled"`
	SampleRate  float64 `json:"sample_rate,omitempty"`   // 0.0 to 1.0 (default: 1.0)
	Filter      string  `json:"filter,omitempty"`        // CEL expression for conditional capture
	MaxBodySize string  `json:"max_body_size,omitempty"` // e.g., "10kb" (default: "10kb")
	Retention   string  `json:"retention,omitempty"`     // e.g., "24h" (default: "24h")
	MaxCount    int     `json:"max_count,omitempty"`     // Max exchanges per site (default: 100000)
}

// CaptureContextKey is the context key for storing capture metadata.
type captureContextKey struct{}

// CaptureContextKeyInstance is the instance of the capture context key.
var CaptureContextKeyInstance = captureContextKey{}

// CaptureMetrics holds counters for capture operations.
type CaptureMetrics struct {
	Captured int64 `json:"captured"`
	Dropped  int64 `json:"dropped"`
	Filtered int64 `json:"filtered"`
	Sampled  int64 `json:"sampled"`
	Errors   int64 `json:"errors"`
}
