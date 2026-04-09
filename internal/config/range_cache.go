// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bytes"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// byteRange represents a single byte range from an RFC 7233 Range header.
type byteRange struct {
	start int64
	end   int64 // inclusive
}

// errRangeNotSatisfiable is returned when the range cannot be satisfied.
var errRangeNotSatisfiable = fmt.Errorf("range not satisfiable")

// parseRangeHeader parses an RFC 7233 Range header value against a known content length.
// It returns the resolved byte ranges or an error if the header is malformed or unsatisfiable.
// Only the "bytes" range unit is supported.
func parseRangeHeader(rangeHeader string, contentLength int64) ([]byteRange, error) {
	if contentLength <= 0 {
		return nil, errRangeNotSatisfiable
	}

	// Must start with "bytes="
	const prefix = "bytes="
	if !strings.HasPrefix(rangeHeader, prefix) {
		return nil, fmt.Errorf("unsupported range unit")
	}

	specs := strings.Split(rangeHeader[len(prefix):], ",")
	if len(specs) == 0 {
		return nil, fmt.Errorf("empty range spec")
	}

	var ranges []byteRange
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}

		dashIdx := strings.IndexByte(spec, '-')
		if dashIdx < 0 {
			return nil, fmt.Errorf("invalid range spec: %q", spec)
		}

		startStr := strings.TrimSpace(spec[:dashIdx])
		endStr := strings.TrimSpace(spec[dashIdx+1:])

		var r byteRange

		if startStr == "" {
			// Suffix range: -500 means last 500 bytes
			if endStr == "" {
				return nil, fmt.Errorf("invalid range spec: %q", spec)
			}
			suffixLen, err := strconv.ParseInt(endStr, 10, 64)
			if err != nil || suffixLen <= 0 {
				return nil, fmt.Errorf("invalid suffix length: %q", endStr)
			}
			if suffixLen > contentLength {
				suffixLen = contentLength
			}
			r.start = contentLength - suffixLen
			r.end = contentLength - 1
		} else {
			// Normal range: start-end or start-
			start, err := strconv.ParseInt(startStr, 10, 64)
			if err != nil || start < 0 {
				return nil, fmt.Errorf("invalid range start: %q", startStr)
			}
			if start >= contentLength {
				return nil, errRangeNotSatisfiable
			}
			r.start = start

			if endStr == "" {
				// Open-ended: start- means start to end of content
				r.end = contentLength - 1
			} else {
				end, err := strconv.ParseInt(endStr, 10, 64)
				if err != nil || end < 0 {
					return nil, fmt.Errorf("invalid range end: %q", endStr)
				}
				// Clamp end to content length - 1
				if end >= contentLength {
					end = contentLength - 1
				}
				if end < start {
					return nil, fmt.Errorf("invalid range: end < start")
				}
				r.end = end
			}
		}

		ranges = append(ranges, r)
	}

	if len(ranges) == 0 {
		return nil, fmt.Errorf("no valid ranges")
	}

	return ranges, nil
}

// buildContentRangeHeader builds an RFC 7233 Content-Range header value.
// Format: bytes start-end/total
func buildContentRangeHeader(start, end, total int64) string {
	return fmt.Sprintf("bytes %d-%d/%d", start, end, total)
}

// buildUnsatisfiedContentRange builds a Content-Range header for 416 responses.
// Format: bytes */total
func buildUnsatisfiedContentRange(total int64) string {
	return fmt.Sprintf("bytes */%d", total)
}

// serveRangeFromCache serves byte ranges from a fully cached response body.
// It writes directly to the ResponseWriter and returns true if the range was served,
// or false if the request should be handled normally (not a range request, or preconditions not met).
func serveRangeFromCache(w http.ResponseWriter, r *http.Request, cachedBody []byte, cachedHeaders http.Header) bool {
	// Only handle GET requests
	if r.Method != http.MethodGet {
		return false
	}

	rangeHeader := r.Header.Get("Range")
	if rangeHeader == "" {
		return false
	}

	contentLength := int64(len(cachedBody))

	// Check If-Range precondition (RFC 7233 Section 3.2).
	// If present, the range request is conditional: only serve ranges if the
	// cached representation matches the validator. Otherwise serve the full response.
	if ifRange := r.Header.Get("If-Range"); ifRange != "" {
		if !evaluateIfRange(ifRange, cachedHeaders) {
			return false // Serve full response instead
		}
	}

	ranges, err := parseRangeHeader(rangeHeader, contentLength)
	if err != nil {
		if err == errRangeNotSatisfiable {
			w.Header().Set("Content-Range", buildUnsatisfiedContentRange(contentLength))
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return true
		}
		// Malformed range header: ignore and serve full response per RFC 7233 Section 3.1
		slog.Debug("ignoring malformed range header",
			"range", rangeHeader,
			"error", err)
		return false
	}

	// Copy relevant headers from the cached response
	copyRangeHeaders(w, cachedHeaders)

	if len(ranges) == 1 {
		serveSingleRange(w, ranges[0], cachedBody, contentLength)
	} else {
		serveMultipleRanges(w, ranges, cachedBody, contentLength, cachedHeaders)
	}

	return true
}

// evaluateIfRange checks whether the If-Range precondition is satisfied.
// If-Range can contain an ETag or an HTTP-date (RFC 7233 Section 3.2).
func evaluateIfRange(ifRange string, cachedHeaders http.Header) bool {
	ifRange = strings.TrimSpace(ifRange)

	// Check if it looks like an ETag (starts with " or W/)
	if strings.HasPrefix(ifRange, "\"") || strings.HasPrefix(ifRange, "W/") {
		cachedETag := cachedHeaders.Get("ETag")
		if cachedETag == "" {
			return false
		}
		// Strong comparison required for If-Range (RFC 7233 Section 3.2)
		// Weak ETags must not match
		if strings.HasPrefix(ifRange, "W/") || strings.HasPrefix(cachedETag, "W/") {
			return false
		}
		return ifRange == cachedETag
	}

	// Otherwise treat as HTTP-date
	ifRangeTime, err := http.ParseTime(ifRange)
	if err != nil {
		return false
	}
	lastModified := cachedHeaders.Get("Last-Modified")
	if lastModified == "" {
		return false
	}
	lmTime, err := http.ParseTime(lastModified)
	if err != nil {
		return false
	}
	return lmTime.Equal(ifRangeTime)
}

// copyRangeHeaders copies safe headers from the cached response to the range response.
func copyRangeHeaders(w http.ResponseWriter, cachedHeaders http.Header) {
	// Headers that should be forwarded in a 206 response
	forwardHeaders := []string{
		"Content-Type",
		"ETag",
		"Last-Modified",
		"Cache-Control",
		"Expires",
		"Date",
		"Accept-Ranges",
	}
	for _, h := range forwardHeaders {
		if v := cachedHeaders.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
}

// serveSingleRange writes a single-range 206 response.
func serveSingleRange(w http.ResponseWriter, br byteRange, body []byte, total int64) {
	rangeLen := br.end - br.start + 1
	w.Header().Set("Content-Range", buildContentRangeHeader(br.start, br.end, total))
	w.Header().Set("Content-Length", strconv.FormatInt(rangeLen, 10))
	w.WriteHeader(http.StatusPartialContent)
	w.Write(body[br.start : br.end+1])
}

// serveMultipleRanges writes a multi-range 206 response with multipart/byteranges encoding.
func serveMultipleRanges(w http.ResponseWriter, ranges []byteRange, body []byte, total int64, cachedHeaders http.Header) {
	contentType := cachedHeaders.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	multipartBody, boundary := buildMultipartRangeResponse(ranges, body, contentType)

	w.Header().Set("Content-Type", fmt.Sprintf("multipart/byteranges; boundary=%s", boundary))
	w.Header().Set("Content-Length", strconv.Itoa(len(multipartBody)))
	// Remove Content-Type from the top level that was copied by copyRangeHeaders;
	// we override it with multipart/byteranges above.
	w.WriteHeader(http.StatusPartialContent)
	w.Write(multipartBody)
}

// buildMultipartRangeResponse builds an RFC 7233 multipart/byteranges response body.
// It returns the encoded body and the boundary string used.
func buildMultipartRangeResponse(ranges []byteRange, body []byte, contentType string) ([]byte, string) {
	boundary := generateBoundary()
	total := int64(len(body))

	var buf bytes.Buffer
	for _, br := range ranges {
		buf.WriteString("--")
		buf.WriteString(boundary)
		buf.WriteString("\r\n")
		buf.WriteString("Content-Type: ")
		buf.WriteString(contentType)
		buf.WriteString("\r\n")
		buf.WriteString("Content-Range: ")
		buf.WriteString(buildContentRangeHeader(br.start, br.end, total))
		buf.WriteString("\r\n\r\n")
		buf.Write(body[br.start : br.end+1])
		buf.WriteString("\r\n")
	}
	buf.WriteString("--")
	buf.WriteString(boundary)
	buf.WriteString("--\r\n")

	return buf.Bytes(), boundary
}

// generateBoundary creates a random MIME boundary string.
func generateBoundary() string {
	// Use a deterministic-length hex string from math/rand for boundary generation.
	// This is not security-sensitive; it only needs to be unique within the response.
	src := rand.New(rand.NewSource(time.Now().UnixNano()))
	return fmt.Sprintf("%016x%016x", src.Int63(), src.Int63())
}
