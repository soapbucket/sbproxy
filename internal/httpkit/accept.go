// Package httpkit provides HTTP utility functions and buffer pools.
package httpkit

import (
	"sort"
	"strconv"
	"strings"
)

// MediaRange represents a parsed Accept header media range with quality.
type MediaRange struct {
	Type    string  // e.g., "application/json"
	Quality float64 // q-value, 0.0-1.0
}

// ParseAccept parses an Accept header into media ranges sorted by quality (descending).
// Each media range may include a q parameter (e.g., "text/html;q=0.9").
// Ranges without a q parameter default to 1.0.
func ParseAccept(header string) []MediaRange {
	if header == "" {
		return nil
	}

	parts := strings.Split(header, ",")
	ranges := make([]MediaRange, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		mr := MediaRange{Quality: 1.0}

		// Split media type from parameters.
		segments := strings.Split(part, ";")
		mr.Type = strings.TrimSpace(segments[0])

		// Look for q parameter.
		for _, seg := range segments[1:] {
			seg = strings.TrimSpace(seg)
			if strings.HasPrefix(seg, "q=") || strings.HasPrefix(seg, "Q=") {
				if q, err := strconv.ParseFloat(seg[2:], 64); err == nil {
					if q >= 0.0 && q <= 1.0 {
						mr.Quality = q
					}
				}
			}
		}

		ranges = append(ranges, mr)
	}

	// Sort by quality descending; preserve order for equal quality.
	sort.SliceStable(ranges, func(i, j int) bool {
		return ranges[i].Quality > ranges[j].Quality
	})

	return ranges
}

// NegotiateContentType selects the best content type from available options
// based on the client's Accept header. It returns the first available type
// that matches a media range (considering wildcards).
// If no match is found, it returns the first available type as a fallback.
func NegotiateContentType(acceptHeader string, available []string) string {
	if len(available) == 0 {
		return ""
	}

	ranges := ParseAccept(acceptHeader)
	if len(ranges) == 0 {
		return available[0]
	}

	// For each preferred range (sorted by quality), find a match.
	for _, mr := range ranges {
		if mr.Quality <= 0 {
			continue
		}
		for _, avail := range available {
			if mediaTypeMatches(mr.Type, avail) {
				return avail
			}
		}
	}

	// No explicit match; fall back to the first available type.
	return available[0]
}

// mediaTypeMatches checks if a media range pattern matches a concrete type.
// Supports exact match and wildcard patterns:
//   - "*/*" matches everything
//   - "text/*" matches any text subtype
//   - "text/html" matches only "text/html"
func mediaTypeMatches(pattern, concrete string) bool {
	if pattern == "*/*" {
		return true
	}

	pParts := strings.SplitN(pattern, "/", 2)
	cParts := strings.SplitN(concrete, "/", 2)

	if len(pParts) != 2 || len(cParts) != 2 {
		return pattern == concrete
	}

	if pParts[0] != cParts[0] && pParts[0] != "*" {
		return false
	}

	if pParts[1] != cParts[1] && pParts[1] != "*" {
		return false
	}

	return true
}
