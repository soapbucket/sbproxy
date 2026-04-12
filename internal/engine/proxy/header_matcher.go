// Package proxy implements the streaming reverse proxy handler and its support types.
package proxy

import (
	"net/http"
	"strings"
)

// HeaderMatcher provides pattern-based header matching with wildcard support
type HeaderMatcher struct {
	patterns []string
}

// NewHeaderMatcher creates a new header matcher
func NewHeaderMatcher(patterns []string) *HeaderMatcher {
	return &HeaderMatcher{
		patterns: patterns,
	}
}

// Matches checks if a header name matches any of the patterns
func (hm *HeaderMatcher) Matches(headerName string) bool {
	for _, pattern := range hm.patterns {
		if hm.matchPattern(headerName, pattern) {
			return true
		}
	}
	return false
}

// matchPattern checks if a header matches a pattern (supports wildcards)
func (hm *HeaderMatcher) matchPattern(header, pattern string) bool {
	// Exact match
	if strings.EqualFold(header, pattern) {
		return true
	}

	// Wildcard match (e.g., "X-Internal-*")
	if strings.Contains(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(strings.ToLower(header), strings.ToLower(prefix))
	}

	return false
}

// StripMatchingHeaders removes headers that match the patterns
func (hm *HeaderMatcher) StripMatchingHeaders(header http.Header) {
	if len(hm.patterns) == 0 {
		return
	}

	// Collect headers to remove
	toRemove := make([]string, 0)
	for name := range header {
		if hm.Matches(name) {
			toRemove = append(toRemove, name)
		}
	}

	// Remove matched headers
	for _, name := range toRemove {
		header.Del(name)
	}
}

