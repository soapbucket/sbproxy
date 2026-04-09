// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"sort"
	"strconv"
	"strings"
)

// MediaRange represents a parsed media type from an Accept header with quality factor.
type MediaRange struct {
	Type    string  // e.g., "text/html", "application/json", "*/*"
	Quality float64 // Quality factor (0.0-1.0), default 1.0
	Params  map[string]string
}

// ParseAcceptHeader parses an Accept header value into ordered MediaRange entries.
// Implements RFC 9110 Section 12.5.1 quality factor parsing.
func ParseAcceptHeader(accept string) []MediaRange {
	if accept == "" {
		return nil
	}

	var ranges []MediaRange
	for _, part := range strings.Split(accept, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		mr := MediaRange{Quality: 1.0, Params: make(map[string]string)}

		// Split media type from parameters
		segments := strings.Split(part, ";")
		mr.Type = strings.TrimSpace(segments[0])

		for _, seg := range segments[1:] {
			seg = strings.TrimSpace(seg)
			if strings.HasPrefix(seg, "q=") || strings.HasPrefix(seg, "Q=") {
				q, err := strconv.ParseFloat(seg[2:], 64)
				if err == nil && q >= 0 && q <= 1 {
					mr.Quality = q
				}
			} else if idx := strings.IndexByte(seg, '='); idx > 0 {
				mr.Params[strings.TrimSpace(seg[:idx])] = strings.TrimSpace(seg[idx+1:])
			}
		}

		ranges = append(ranges, mr)
	}

	// Sort by quality (highest first), then by specificity
	sort.SliceStable(ranges, func(i, j int) bool {
		if ranges[i].Quality != ranges[j].Quality {
			return ranges[i].Quality > ranges[j].Quality
		}
		// More specific types take precedence
		return mediaSpecificity(ranges[i].Type) > mediaSpecificity(ranges[j].Type)
	})

	return ranges
}

// ParseAcceptEncodingHeader parses Accept-Encoding with quality factors.
// Returns encodings sorted by quality (highest first).
func ParseAcceptEncodingHeader(header string) []EncodingPreference {
	if header == "" {
		return nil
	}

	var prefs []EncodingPreference
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		ep := EncodingPreference{Quality: 1.0}

		if idx := strings.Index(part, ";"); idx >= 0 {
			remainder := strings.TrimSpace(part[idx+1:])
			part = strings.TrimSpace(part[:idx])
			if strings.HasPrefix(remainder, "q=") || strings.HasPrefix(remainder, "Q=") {
				q, err := strconv.ParseFloat(remainder[2:], 64)
				if err == nil && q >= 0 && q <= 1 {
					ep.Quality = q
				}
			}
		}

		ep.Encoding = part
		if ep.Quality > 0 {
			prefs = append(prefs, ep)
		}
	}

	sort.SliceStable(prefs, func(i, j int) bool {
		return prefs[i].Quality > prefs[j].Quality
	})

	return prefs
}

// EncodingPreference represents a parsed encoding preference.
type EncodingPreference struct {
	Encoding string
	Quality  float64
}

// ParseAcceptLanguageHeader parses Accept-Language with quality factors.
func ParseAcceptLanguageHeader(header string) []LanguagePreference {
	if header == "" {
		return nil
	}

	var prefs []LanguagePreference
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		lp := LanguagePreference{Quality: 1.0}

		if idx := strings.Index(part, ";"); idx >= 0 {
			remainder := strings.TrimSpace(part[idx+1:])
			part = strings.TrimSpace(part[:idx])
			if strings.HasPrefix(remainder, "q=") || strings.HasPrefix(remainder, "Q=") {
				q, err := strconv.ParseFloat(remainder[2:], 64)
				if err == nil && q >= 0 && q <= 1 {
					lp.Quality = q
				}
			}
		}

		lp.Language = part
		if lp.Quality > 0 {
			prefs = append(prefs, lp)
		}
	}

	sort.SliceStable(prefs, func(i, j int) bool {
		return prefs[i].Quality > prefs[j].Quality
	})

	return prefs
}

// LanguagePreference represents a parsed language preference.
type LanguagePreference struct {
	Language string
	Quality  float64
}

// mediaSpecificity returns a specificity score for media type ordering.
// */* = 0, type/* = 1, type/subtype = 2, type/subtype;params = 3
func mediaSpecificity(mediaType string) int {
	if mediaType == "*/*" {
		return 0
	}
	if strings.HasSuffix(mediaType, "/*") {
		return 1
	}
	return 2
}

// BestAcceptMatch returns the best matching content type from available types
// based on the parsed Accept header preferences.
func BestAcceptMatch(available []string, accept []MediaRange) string {
	if len(accept) == 0 || len(available) == 0 {
		if len(available) > 0 {
			return available[0]
		}
		return ""
	}

	for _, mr := range accept {
		for _, ct := range available {
			if matchesMediaRange(ct, mr.Type) {
				return ct
			}
		}
	}

	return ""
}

// matchesMediaRange checks if a content type matches a media range pattern.
func matchesMediaRange(contentType, pattern string) bool {
	if pattern == "*/*" {
		return true
	}

	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(contentType, prefix+"/")
	}

	// Extract media type without parameters
	ct := contentType
	if idx := strings.IndexByte(ct, ';'); idx >= 0 {
		ct = strings.TrimSpace(ct[:idx])
	}
	pt := pattern
	if idx := strings.IndexByte(pt, ';'); idx >= 0 {
		pt = strings.TrimSpace(pt[:idx])
	}

	return strings.EqualFold(ct, pt)
}
