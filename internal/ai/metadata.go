// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"net/http"
	"strings"
)

const metaHeaderPrefix = "x-sb-meta-"

// ExtractMetadata extracts X-Sb-Meta-* headers from the request and returns
// them as a map keyed by the suffix (lowercased). For example, the header
// "X-Sb-Meta-Team" produces the key "team".
func ExtractMetadata(r *http.Request) map[string]string {
	if r == nil {
		return nil
	}
	return ExtractMetadataFromHeaders(r.Header)
}

// ExtractMetadataFromHeaders extracts X-Sb-Meta-* entries from raw HTTP headers.
func ExtractMetadataFromHeaders(h http.Header) map[string]string {
	var meta map[string]string
	for key, values := range h {
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, metaHeaderPrefix) {
			name := lower[len(metaHeaderPrefix):]
			if name == "" || len(values) == 0 {
				continue
			}
			if meta == nil {
				meta = make(map[string]string)
			}
			meta[name] = values[0]
		}
	}
	return meta
}
