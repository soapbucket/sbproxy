// Package action contains action-level traffic management handlers.
package action

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// GRPCWebConfig configures gRPC-Web to gRPC transcoding.
type GRPCWebConfig struct {
	Enabled bool `json:"enabled,omitempty" yaml:"enabled"`
}

// IsGRPCWebRequest checks if the request uses gRPC-Web protocol.
func IsGRPCWebRequest(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	return strings.HasPrefix(ct, "application/grpc-web") ||
		strings.HasPrefix(ct, "application/grpc-web+proto") ||
		strings.HasPrefix(ct, "application/grpc-web-text")
}

// isGRPCWebText returns true if the request uses the text (base64) variant.
func isGRPCWebText(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	return strings.HasPrefix(ct, "application/grpc-web-text")
}

// TranscodeGRPCWebRequest converts a gRPC-Web request to standard gRPC.
// It rewrites the Content-Type header and decodes base64 bodies for
// the grpc-web-text variant.
func TranscodeGRPCWebRequest(r *http.Request) error {
	ct := r.Header.Get("Content-Type")

	// Determine the underlying sub-type (e.g., "+proto") for mapping.
	suffix := ""
	if idx := strings.Index(ct, "+"); idx >= 0 {
		suffix = ct[idx:]
	}

	if isGRPCWebText(r) {
		// Base64-decode the body for text variant.
		if r.Body != nil {
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				return fmt.Errorf("grpc-web: read text body: %w", err)
			}
			_ = r.Body.Close()

			decoded, err := base64.StdEncoding.DecodeString(string(raw))
			if err != nil {
				return fmt.Errorf("grpc-web: decode base64 body: %w", err)
			}
			r.Body = io.NopCloser(bytes.NewReader(decoded))
			r.ContentLength = int64(len(decoded))
		}
	}

	// Rewrite content type from grpc-web to grpc.
	r.Header.Set("Content-Type", "application/grpc"+suffix)

	return nil
}

// TranscodeGRPCWebResponse converts a standard gRPC response to gRPC-Web format.
// It rewrites the Content-Type header and, when isText is true, base64-encodes
// the response body. gRPC trailers are appended as a length-prefixed trailer frame
// per the gRPC-Web specification.
func TranscodeGRPCWebResponse(w http.ResponseWriter, resp *http.Response, isText bool) error {
	if resp == nil {
		return fmt.Errorf("grpc-web: response must not be nil")
	}

	// Determine output content type.
	ct := resp.Header.Get("Content-Type")
	suffix := ""
	if idx := strings.Index(ct, "+"); idx >= 0 {
		suffix = ct[idx:]
	}

	if isText {
		w.Header().Set("Content-Type", "application/grpc-web-text"+suffix)
	} else {
		w.Header().Set("Content-Type", "application/grpc-web"+suffix)
	}

	// Copy non-trailer response headers.
	for k, vs := range resp.Header {
		if strings.EqualFold(k, "Content-Type") {
			continue
		}
		if strings.EqualFold(k, "Trailer") {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(resp.StatusCode)

	// Read the body.
	var body []byte
	if resp.Body != nil {
		var err error
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("grpc-web: read response body: %w", err)
		}
		_ = resp.Body.Close()
	}

	// Build the trailer frame (0x80 flag, then length-prefixed trailer data).
	var trailerBuf bytes.Buffer
	for k, vs := range resp.Trailer {
		for _, v := range vs {
			trailerBuf.WriteString(k)
			trailerBuf.WriteString(": ")
			trailerBuf.WriteString(v)
			trailerBuf.WriteString("\r\n")
		}
	}
	trailerBytes := trailerBuf.Bytes()

	if isText {
		// Combine body + trailer frame, then base64-encode everything.
		var combined bytes.Buffer
		combined.Write(body)

		if len(trailerBytes) > 0 {
			// Trailer frame: 1-byte flag (0x80) + 4-byte length + trailer data
			var frame [5]byte
			frame[0] = 0x80
			binary.BigEndian.PutUint32(frame[1:], uint32(len(trailerBytes)))
			combined.Write(frame[:])
			combined.Write(trailerBytes)
		}

		encoded := base64.StdEncoding.EncodeToString(combined.Bytes())
		_, err := io.WriteString(w, encoded)
		return err
	}

	// Binary variant: write body then trailer frame.
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("grpc-web: write body: %w", err)
	}

	if len(trailerBytes) > 0 {
		var frame [5]byte
		frame[0] = 0x80
		binary.BigEndian.PutUint32(frame[1:], uint32(len(trailerBytes)))
		if _, err := w.Write(frame[:]); err != nil {
			return fmt.Errorf("grpc-web: write trailer frame header: %w", err)
		}
		if _, err := w.Write(trailerBytes); err != nil {
			return fmt.Errorf("grpc-web: write trailer data: %w", err)
		}
	}

	return nil
}
