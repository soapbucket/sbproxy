// Package cache implements semantic caching for AI responses using vector similarity search.
package cache

import "strings"

// CacheDirective represents parsed cache control instructions from request headers.
type CacheDirective struct {
	NoCache    bool // Bypass cache read, but store the new result
	NoStore    bool // Bypass cache entirely (no read, no write)
	ForceCache bool // Return cached response even if stale
}

// CacheStatus represents the result of a cache operation for response headers.
type CacheStatus string

const (
	CacheStatusHit         CacheStatus = "hit"
	CacheStatusMiss        CacheStatus = "miss"
	CacheStatusSemanticHit CacheStatus = "semantic_hit"
	CacheStatusBypass      CacheStatus = "bypass"
	CacheStatusNoStore     CacheStatus = "no-store"
)

// HeaderSBCacheControl is the request header for cache control directives.
const HeaderSBCacheControl = "X-Sb-Cache-Control"

// HeaderSBCacheStatus is the response header indicating cache result.
const HeaderSBCacheStatus = "X-Sb-Cache-Status"

// ParseCacheControl parses the X-Sb-Cache-Control header value into a CacheDirective.
// Supports: "no-cache", "no-store", "force-cache".
// Multiple directives can be comma-separated.
func ParseCacheControl(header string) CacheDirective {
	var d CacheDirective
	if header == "" {
		return d
	}

	parts := strings.Split(header, ",")
	for _, part := range parts {
		switch strings.TrimSpace(strings.ToLower(part)) {
		case "no-cache":
			d.NoCache = true
		case "no-store":
			d.NoStore = true
		case "force-cache":
			d.ForceCache = true
		}
	}

	return d
}

// ShouldRead returns true if the cache should be consulted for a cached response.
// Returns false for no-cache and no-store directives.
func (d CacheDirective) ShouldRead() bool {
	return !d.NoCache && !d.NoStore
}

// ShouldWrite returns true if the response should be stored in the cache.
// Returns false for no-store directive.
func (d CacheDirective) ShouldWrite() bool {
	return !d.NoStore
}

// Status returns the appropriate CacheStatus based on the directive.
// Used when a directive causes the cache to be bypassed entirely.
func (d CacheDirective) Status() CacheStatus {
	if d.NoStore {
		return CacheStatusNoStore
	}
	if d.NoCache {
		return CacheStatusBypass
	}
	return CacheStatusMiss
}
