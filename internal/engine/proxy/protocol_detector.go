// Package proxy implements the streaming reverse proxy handler and its support types.
package proxy

import (
	"net/http"
	"strings"
)

// Protocol represents the detected protocol type
type Protocol string

const (
	// ProtocolHTTP1 is a constant for protocol http1.
	ProtocolHTTP1              Protocol = "http1"
	// ProtocolHTTP2 is a constant for protocol http2.
	ProtocolHTTP2              Protocol = "http2"
	// ProtocolHTTP2Bidirectional is a constant for protocol http2 bidirectional.
	ProtocolHTTP2Bidirectional Protocol = "http2_bidirectional"
	// ProtocolHTTP3 is a constant for protocol http3.
	ProtocolHTTP3              Protocol = "http3"
	// ProtocolWebSocket is a constant for protocol web socket.
	ProtocolWebSocket          Protocol = "websocket"
	// ProtocolGRPC is a constant for protocol grpc.
	ProtocolGRPC               Protocol = "grpc"
)

// ProtocolDetector detects the protocol from the request
type ProtocolDetector struct{}

// NewProtocolDetector creates a new protocol detector
func NewProtocolDetector() *ProtocolDetector {
	return &ProtocolDetector{}
}

// Detect determines the protocol from the request
func (pd *ProtocolDetector) Detect(r *http.Request) Protocol {
	// Check for WebSocket upgrade
	if r.Header.Get("Upgrade") == "websocket" &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		return ProtocolWebSocket
	}

	// Check for gRPC (content-type based)
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/grpc") {
		return ProtocolGRPC
	}

	// Check HTTP version
	if r.ProtoMajor == 3 {
		return ProtocolHTTP3
	}

	if r.ProtoMajor == 2 {
		// Check for bidirectional streaming indicators
		// Only treat as bidirectional if there are multiple signals:
		// 1. Accept-Encoding is identity or empty (client disabled compression)
		// 2. AND one of:
		//    - Content-Type suggests streaming (application/x-ndjson, text/event-stream)
		//    - Explicit streaming header present
		ae := r.Header.Get("Accept-Encoding")
		if ae == "identity" || ae == "" {
			ct := r.Header.Get("Content-Type")
			// Check for streaming content types or explicit streaming intent
			if strings.HasPrefix(ct, "application/x-ndjson") ||
				strings.HasPrefix(ct, "text/event-stream") ||
				strings.HasPrefix(ct, "application/stream+json") ||
				r.Header.Get("X-Stream-Mode") == "bidirectional" {
				return ProtocolHTTP2Bidirectional
			}
			// Empty Accept-Encoding alone is not enough - many clients don't send it
		}
		return ProtocolHTTP2
	}

	return ProtocolHTTP1
}

