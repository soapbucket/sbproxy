// Package httputil defines HTTP constants, header names, and shared request/response utilities.
package httputil

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

const (
	// DefaultMaxBufferedBodySize is the default maximum body size before streaming fallback (10MB)
	DefaultMaxBufferedBodySize = 10 * 1024 * 1024

	// DefaultMaxProcessableBodySize is the default maximum body size to process at all (100MB)
	DefaultMaxProcessableBodySize = 100 * 1024 * 1024

	// DefaultModifierThreshold is the default threshold for body modifications (10MB)
	DefaultModifierThreshold = 10 * 1024 * 1024

	// DefaultTransformThreshold is the default threshold for transformations (10MB)
	DefaultTransformThreshold = 10 * 1024 * 1024

	// DefaultSignatureThreshold is the default threshold for signature verification (50MB)
	DefaultSignatureThreshold = 50 * 1024 * 1024

	// DefaultCallbackThreshold is the default threshold for callback responses (1MB)
	DefaultCallbackThreshold = 1 * 1024 * 1024
)

// parseSize parses a size string (e.g., "10MB", "100KB") to bytes
func parseSize(sizeStr string, defaultSize int64) int64 {
	if sizeStr == "" {
		return defaultSize
	}

	sizeStr = strings.TrimSpace(strings.ToUpper(sizeStr))

	// Extract number and unit
	var numStr string
	var unit string
	hasDecimal := false
	for i, r := range sizeStr {
		if r >= '0' && r <= '9' {
			numStr += string(r)
		} else if r == '.' && !hasDecimal {
			// Allow one decimal point
			numStr += string(r)
			hasDecimal = true
		} else {
			unit = sizeStr[i:]
			break
		}
	}

	if numStr == "" {
		return defaultSize
	}

	// Parse as float64 first to handle decimals, then truncate to int64
	numFloat, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return defaultSize
	}
	num := int64(numFloat) // Truncate decimal part

	var multiplier int64
	switch unit {
	case "KB", "K":
		multiplier = 1024
	case "MB", "M":
		multiplier = 1024 * 1024
	case "GB", "G":
		multiplier = 1024 * 1024 * 1024
	case "TB", "T":
		multiplier = 1024 * 1024 * 1024 * 1024
	case "B", "":
		multiplier = 1
	default:
		return defaultSize
	}

	return num * multiplier
}

// GetStreamingThresholds returns streaming thresholds from config values, with defaults applied
func GetStreamingThresholds(enabled bool, maxBufferedBodySize, maxProcessableBodySize, modifierThreshold, transformThreshold, signatureThreshold, callbackThreshold string) *StreamingThresholds {
	// Default to enabled if not explicitly disabled and no config provided
	if !enabled && maxBufferedBodySize == "" {
		// If not configured at all, default to enabled
		enabled = true
	}

	return &StreamingThresholds{
		Enabled:                enabled,
		MaxBufferedBodySize:    parseSize(maxBufferedBodySize, DefaultMaxBufferedBodySize),
		MaxProcessableBodySize: parseSize(maxProcessableBodySize, DefaultMaxProcessableBodySize),
		ModifierThreshold:      parseSize(modifierThreshold, DefaultModifierThreshold),
		TransformThreshold:     parseSize(transformThreshold, DefaultTransformThreshold),
		SignatureThreshold:     parseSize(signatureThreshold, DefaultSignatureThreshold),
		CallbackThreshold:      parseSize(callbackThreshold, DefaultCallbackThreshold),
	}
}

// StreamingThresholds holds parsed streaming thresholds
type StreamingThresholds struct {
	Enabled                bool
	MaxBufferedBodySize    int64
	MaxProcessableBodySize int64
	ModifierThreshold      int64
	TransformThreshold     int64
	SignatureThreshold     int64
	CallbackThreshold      int64
}

// SizeTracker wraps a reader to track bytes read and detect threshold breaches
type SizeTracker struct {
	reader    io.ReadCloser
	threshold int64
	bytesRead int64
	exceeded  bool
	mu        sync.Mutex
}

// NewSizeTracker creates a new size tracker
func NewSizeTracker(reader io.ReadCloser, threshold int64) *SizeTracker {
	return &SizeTracker{
		reader:    reader,
		threshold: threshold,
	}
}

// Read implements io.Reader
func (st *SizeTracker) Read(p []byte) (n int, err error) {
	st.mu.Lock()
	defer st.mu.Unlock()

	n, err = st.reader.Read(p)
	st.bytesRead += int64(n)

	if st.bytesRead > st.threshold && !st.exceeded {
		st.exceeded = true
		slog.Warn("Body size exceeded threshold",
			"bytes_read", st.bytesRead,
			"threshold", st.threshold)
	}

	return n, err
}

// Close implements io.Closer
func (st *SizeTracker) Close() error {
	return st.reader.Close()
}

// BytesRead returns the number of bytes read
func (st *SizeTracker) BytesRead() int64 {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.bytesRead
}

// Exceeded returns whether the threshold was exceeded
func (st *SizeTracker) Exceeded() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.exceeded
}

// Original returns the original reader (for restoring)
func (st *SizeTracker) Original() io.ReadCloser {
	return st.reader
}

// ShouldStream checks if a response should be streamed based on Content-Length
func ShouldStream(resp *http.Response, threshold int64) bool {
	if resp == nil {
		return false
	}

	// Check Content-Length header
	if resp.ContentLength > 0 {
		return resp.ContentLength > threshold
	}

	// If Content-Length is unknown, we'll need to check during read
	// For now, default to not streaming if unknown
	return false
}

// CheckBodySize checks if a body size exceeds the threshold and returns an error if it does
func CheckBodySize(contentLength int64, maxSize int64) error {
	if contentLength > 0 && contentLength > maxSize {
		return fmt.Errorf("body size %d exceeds maximum processable size %d", contentLength, maxSize)
	}
	return nil
}

// WrapResponseWithSizeLimit wraps a response body with a size-limited reader
func WrapResponseWithSizeLimit(resp *http.Response, maxSize int64) *http.Response {
	if resp == nil || resp.Body == nil {
		return resp
	}

	// Check Content-Length first
	if resp.ContentLength > 0 && resp.ContentLength > maxSize {
		slog.Warn("Response body exceeds maximum processable size, wrapping with limit",
			"content_length", resp.ContentLength,
			"max_size", maxSize)
		resp.Body = http.MaxBytesReader(nil, resp.Body, maxSize)
		return resp
	}

	// Wrap with size tracker to monitor during read
	tracker := NewSizeTracker(resp.Body, maxSize)
	resp.Body = tracker
	return resp
}
