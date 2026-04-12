// Package proxy implements the streaming reverse proxy handler and its support types.
package proxy

import (
	"net/http"
	"strings"
	"time"
)

// FlushStrategy defines how response body should be flushed
type FlushStrategy struct {
	Type        FlushType
	Interval    time.Duration // -1 = immediate, 0 = buffered, >0 = periodic
	Reason      string
	IsStreaming bool
}

// FlushType represents the type of flush strategy
type FlushType string

const (
	// FlushImmediate is a constant for flush immediate.
	FlushImmediate FlushType = "immediate" // Flush after every write
	// FlushPeriodic is a constant for flush periodic.
	FlushPeriodic FlushType = "periodic" // Flush at intervals
	// FlushBuffered is a constant for flush buffered.
	FlushBuffered FlushType = "buffered" // No explicit flushing
)

// FlushController determines optimal flush strategy
type FlushController struct {
	defaultInterval time.Duration
}

// NewFlushController creates a new flush controller
func NewFlushController() *FlushController {
	return &FlushController{
		defaultInterval: 100 * time.Millisecond,
	}
}

// DetermineStrategy analyzes request/response to determine flush strategy
func (fc *FlushController) DetermineStrategy(req *http.Request, resp *http.Response) FlushStrategy {
	contentType := resp.Header.Get("Content-Type")

	// 1. Server-Sent Events: always flush immediately
	if contentType == "text/event-stream" {
		return FlushStrategy{
			Type:        FlushImmediate,
			Interval:    -1,
			Reason:      "sse",
			IsStreaming: true,
		}
	}

	// 2. gRPC: flush immediately for streaming RPCs
	if strings.HasPrefix(contentType, "application/grpc") {
		return FlushStrategy{
			Type:        FlushImmediate,
			Interval:    -1,
			Reason:      "grpc",
			IsStreaming: true,
		}
	}

	// 3. HTTP/2 bidirectional streaming
	if fc.isBidirectionalStream(req, resp) {
		return FlushStrategy{
			Type:        FlushImmediate,
			Interval:    -1,
			Reason:      "http2_bidirectional",
			IsStreaming: true,
		}
	}

	// 4. Unknown content length: likely streaming
	if resp.ContentLength == -1 {
		// Check for chunked transfer encoding
		if fc.isChunkedTransfer(resp) {
			return FlushStrategy{
				Type:        FlushImmediate,
				Interval:    -1,
				Reason:      "chunked_transfer",
				IsStreaming: true,
			}
		}

		// Unknown length but not explicitly chunked - use periodic flushing
		return FlushStrategy{
			Type:        FlushPeriodic,
			Interval:    fc.defaultInterval,
			Reason:      "unknown_length",
			IsStreaming: false,
		}
	}

	// 5. Streaming content types (video, audio)
	if fc.isStreamingContentType(contentType) {
		return FlushStrategy{
			Type:        FlushPeriodic,
			Interval:    50 * time.Millisecond, // More frequent for media
			Reason:      "streaming_media",
			IsStreaming: true,
		}
	}

	// 6. Large responses: periodic flushing to reduce memory
	if resp.ContentLength > 1024*1024 { // > 1MB
		return FlushStrategy{
			Type:        FlushPeriodic,
			Interval:    fc.defaultInterval,
			Reason:      "large_response",
			IsStreaming: false,
		}
	}

	// 7. Default: buffered (let Go handle it)
	return FlushStrategy{
		Type:        FlushBuffered,
		Interval:    0,
		Reason:      "buffered",
		IsStreaming: false,
	}
}

// isBidirectionalStream detects HTTP/2 bidirectional streaming
func (fc *FlushController) isBidirectionalStream(req *http.Request, resp *http.Response) bool {
	if req.ProtoMajor != 2 || resp.ProtoMajor != 2 {
		return false
	}

	if resp.ContentLength != -1 {
		return false
	}

	// Check if client disabled compression (signal for streaming)
	ae := req.Header.Get("Accept-Encoding")
	if ae != "identity" && ae != "" {
		return false
	}

	// Require additional streaming signals beyond just missing Accept-Encoding
	ct := resp.Header.Get("Content-Type")
	return strings.HasPrefix(ct, "application/x-ndjson") ||
		strings.HasPrefix(ct, "text/event-stream") ||
		strings.HasPrefix(ct, "application/stream+json") ||
		req.Header.Get("X-Stream-Mode") == "bidirectional"
}

// isChunkedTransfer checks if response uses chunked transfer encoding
func (fc *FlushController) isChunkedTransfer(resp *http.Response) bool {
	for _, enc := range resp.TransferEncoding {
		if enc == "chunked" {
			return true
		}
	}
	return false
}

// isStreamingContentType checks if content type is typically streamed
func (fc *FlushController) isStreamingContentType(ct string) bool {
	streamingTypes := []string{
		"video/",
		"audio/",
		"application/octet-stream",
		"application/x-ndjson",
		"application/stream+json",
	}

	for _, prefix := range streamingTypes {
		if strings.HasPrefix(ct, prefix) {
			return true
		}
	}

	return false
}
