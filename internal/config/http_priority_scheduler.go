// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"net/http"
	"strconv"
	"strings"
)

// PrioritySchedulerConfig configures RFC 9218 priority-based response scheduling.
// When enabled, the proxy parses the Priority header and adjusts flush behavior
// based on urgency and incremental flags.
type PrioritySchedulerConfig struct {
	// Enable priority-based response scheduling.
	// Default: false
	Enable bool `json:"enable,omitempty" yaml:"enable,omitempty"`
}

// defaultUrgency is the RFC 9218 default urgency when no Priority header is present.
const defaultUrgency = 3

// parsePriorityHeader parses an RFC 9218 Priority header value.
// The header uses structured fields: "u=N" for urgency (0-7, lower = more urgent)
// and "i" for the incremental flag.
// Returns the urgency level and whether the incremental flag is set.
// On missing or invalid input, returns default urgency (3) and false.
func parsePriorityHeader(header string) (urgency int, incremental bool) {
	urgency = defaultUrgency
	if header == "" {
		return urgency, false
	}

	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "u=") {
			val := strings.TrimPrefix(part, "u=")
			if n, err := strconv.Atoi(val); err == nil && n >= 0 && n <= 7 {
				urgency = n
			}
		} else if part == "i" {
			incremental = true
		}
	}

	return urgency, incremental
}

// PriorityResponseWriter wraps an http.ResponseWriter and adjusts flush behavior
// based on the RFC 9218 Priority header values.
//
// Flush behavior by urgency:
//   - High urgency (u=0-2): flush immediately after each write
//   - Medium urgency (u=3-5): use normal buffered flush
//   - Low urgency (u=6-7): larger buffer, less frequent flushes
//   - Incremental flag (i): always flush immediately (used for streaming)
type PriorityResponseWriter struct {
	http.ResponseWriter
	urgency     int
	incremental bool
	buf         []byte
	bufSize     int
	flushed     bool
}

// NewPriorityResponseWriter creates a PriorityResponseWriter that wraps the given
// ResponseWriter with flush behavior derived from the request's Priority header.
func NewPriorityResponseWriter(w http.ResponseWriter, r *http.Request, cfg *PrioritySchedulerConfig) *PriorityResponseWriter {
	if cfg == nil || !cfg.Enable {
		return &PriorityResponseWriter{
			ResponseWriter: w,
			urgency:        defaultUrgency,
			bufSize:        0, // No buffering, pass through
		}
	}

	urgency, incremental := parsePriorityHeader(r.Header.Get("Priority"))

	var bufSize int
	switch {
	case incremental:
		bufSize = 0 // Always flush immediately for incremental streams
	case urgency <= 2:
		bufSize = 0 // High urgency: flush immediately
	case urgency <= 5:
		bufSize = 4096 // Medium urgency: 4KB buffer
	default:
		bufSize = 32768 // Low urgency (6-7): 32KB buffer
	}

	return &PriorityResponseWriter{
		ResponseWriter: w,
		urgency:        urgency,
		incremental:    incremental,
		bufSize:        bufSize,
	}
}

// Write writes data to the underlying ResponseWriter, applying priority-based
// buffering and flush behavior.
func (pw *PriorityResponseWriter) Write(b []byte) (int, error) {
	// No buffering: write and flush immediately
	if pw.bufSize == 0 {
		n, err := pw.ResponseWriter.Write(b)
		if err != nil {
			return n, err
		}
		pw.flushUnderlying()
		return n, nil
	}

	// Buffered write
	pw.buf = append(pw.buf, b...)
	if len(pw.buf) >= pw.bufSize {
		return len(b), pw.flushBuffer()
	}
	return len(b), nil
}

// Flush implements http.Flusher and flushes any buffered data.
func (pw *PriorityResponseWriter) Flush() {
	if len(pw.buf) > 0 {
		pw.flushBuffer()
	}
	pw.flushUnderlying()
}

// flushBuffer writes buffered data to the underlying writer and clears the buffer.
func (pw *PriorityResponseWriter) flushBuffer() error {
	if len(pw.buf) == 0 {
		return nil
	}
	_, err := pw.ResponseWriter.Write(pw.buf)
	pw.buf = pw.buf[:0]
	if err != nil {
		return err
	}
	pw.flushUnderlying()
	return nil
}

// flushUnderlying calls Flush on the underlying ResponseWriter if it supports it.
func (pw *PriorityResponseWriter) flushUnderlying() {
	if f, ok := pw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap returns the underlying ResponseWriter for http.ResponseController compatibility.
func (pw *PriorityResponseWriter) Unwrap() http.ResponseWriter {
	return pw.ResponseWriter
}

// Urgency returns the parsed urgency level.
func (pw *PriorityResponseWriter) Urgency() int {
	return pw.urgency
}

// Incremental returns whether the incremental flag was set.
func (pw *PriorityResponseWriter) Incremental() bool {
	return pw.incremental
}
