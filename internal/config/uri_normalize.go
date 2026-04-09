// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"net/http"
	"net/url"
	"path"
	"strings"
)

// normalizeRequestURI applies URI normalization per RFC 3986 Section 6.
func normalizeRequestURI(r *http.Request, cfg *URINormalizationConfig) {
	if cfg == nil || !cfg.Enable {
		return
	}

	u := r.URL

	// Lowercase scheme and host (RFC 3986 Section 3.1, 3.2.2)
	if cfg.LowercaseSchemeHost == nil || *cfg.LowercaseSchemeHost {
		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
	}

	// Decode dot segments (RFC 3986 Section 5.2.4)
	if cfg.DecodeDotSegments == nil || *cfg.DecodeDotSegments {
		if u.Path != "" {
			cleaned := path.Clean(u.Path)
			// path.Clean removes trailing slash; preserve it if original had one
			if strings.HasSuffix(u.Path, "/") && !strings.HasSuffix(cleaned, "/") {
				cleaned += "/"
			}
			// path.Clean may return "." for empty path
			if cleaned == "." {
				cleaned = "/"
			}
			u.Path = cleaned
		}
	}

	// Merge consecutive slashes
	if cfg.MergeSlashes == nil || *cfg.MergeSlashes {
		if strings.Contains(u.Path, "//") {
			u.Path = mergeSlashes(u.Path)
		}
	}

	// Decode unreserved percent-encoded characters (RFC 3986 Section 2.3)
	if cfg.DecodeUnreserved == nil || *cfg.DecodeUnreserved {
		if strings.Contains(u.Path, "%") {
			u.Path = decodeUnreservedChars(u.Path)
		}
		if strings.Contains(u.RawQuery, "%") {
			u.RawQuery = decodeUnreservedChars(u.RawQuery)
		}
	}
}

// mergeSlashes replaces consecutive slashes with a single slash.
func mergeSlashes(p string) string {
	var b strings.Builder
	b.Grow(len(p))
	prev := byte(0)
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '/' && prev == '/' {
			continue
		}
		b.WriteByte(c)
		prev = c
	}
	return b.String()
}

// decodeUnreservedChars decodes percent-encoded unreserved characters.
// Unreserved characters (RFC 3986 Section 2.3): ALPHA, DIGIT, '-', '.', '_', '~'
func decodeUnreservedChars(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi := unhex(s[i+1])
			lo := unhex(s[i+2])
			if hi >= 0 && lo >= 0 {
				c := byte(hi<<4 | lo)
				if isUnreserved(c) {
					b.WriteByte(c)
					i += 2
					continue
				}
				// Normalize hex digits to uppercase for reserved chars
				b.WriteByte('%')
				b.WriteByte(upperHex(s[i+1]))
				b.WriteByte(upperHex(s[i+2]))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isUnreserved(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~'
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func upperHex(c byte) byte {
	if c >= 'a' && c <= 'f' {
		return c - 32
	}
	return c
}

// NormalizeCacheKeyURI normalizes a URL for use as a cache key.
func NormalizeCacheKeyURI(u *url.URL) string {
	normalized := *u
	normalized.Scheme = strings.ToLower(normalized.Scheme)
	normalized.Host = strings.ToLower(normalized.Host)
	if normalized.Path != "" {
		normalized.Path = path.Clean(normalized.Path)
		if strings.HasSuffix(u.Path, "/") && !strings.HasSuffix(normalized.Path, "/") {
			normalized.Path += "/"
		}
	}
	return normalized.String()
}
