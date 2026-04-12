// Package callback executes HTTP callbacks to external services during request processing with retry and caching support.
package callback

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pquerna/cachecontrol/cacheobject"
	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
)

const (
	// Default stale-while-revalidate duration if not specified
	defaultStaleWhileRevalidate = 60 * time.Second

	// Default stale-if-error duration if not specified
	defaultStaleIfError = 300 * time.Second
)

// CacheState represents the state of a cached response
type CacheState int

const (
	// StateFresh is a constant for state fresh.
	StateFresh CacheState = iota
	// StateStale is a constant for state stale.
	StateStale
	// StateStaleError is a constant for state stale error.
	StateStaleError
	// StateExpired is a constant for state expired.
	StateExpired
)

// String returns a human-readable representation of the CacheState.
func (s CacheState) String() string {
	switch s {
	case StateFresh:
		return "fresh"
	case StateStale:
		return "stale"
	case StateStaleError:
		return "stale-error"
	case StateExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// CacheMetadata contains HTTP cache metadata parsed from response headers
type CacheMetadata struct {
	// HTTP cache headers
	ETag         string
	LastModified time.Time
	VaryHeaders  []string

	// Cache-Control directives
	MaxAge               time.Duration
	StaleWhileRevalidate time.Duration
	StaleIfError         time.Duration
	MustRevalidate       bool
	NoCache              bool
	NoStore              bool
	Private              bool
	Public               bool

	// Calculated expiration times
	ExpiresAt  time.Time // Fresh until this time
	StaleAt    time.Time // Stale but usable until this time
	MaxStaleAt time.Time // Absolute expiry (stale-if-error)
}

// HTTPCacheParser parses HTTP cache headers from responses
type HTTPCacheParser struct {
	defaultStaleWhileRevalidate time.Duration
	defaultStaleIfError         time.Duration
}

// NewHTTPCacheParser creates a new HTTP cache parser
func NewHTTPCacheParser(swrDuration, sieDuration time.Duration) *HTTPCacheParser {
	swr := swrDuration
	if swr <= 0 {
		swr = defaultStaleWhileRevalidate
	}

	sie := sieDuration
	if sie <= 0 {
		sie = defaultStaleIfError
	}

	return &HTTPCacheParser{
		defaultStaleWhileRevalidate: swr,
		defaultStaleIfError:         sie,
	}
}

// ParseResponse parses HTTP cache headers from a response
func (p *HTTPCacheParser) ParseResponse(resp *http.Response) (*CacheMetadata, error) {
	metadata := &CacheMetadata{
		VaryHeaders: []string{},
	}

	now := time.Now()

	// Extract ETag
	metadata.ETag = resp.Header.Get(httputil.HeaderETag)
	if metadata.ETag != "" {
		// Remove quotes if present
		metadata.ETag = strings.Trim(metadata.ETag, `"`)
	}

	// Extract Last-Modified
	if lastModStr := resp.Header.Get(httputil.HeaderLastModified); lastModStr != "" {
		if t, err := time.Parse(time.RFC1123, lastModStr); err == nil {
			metadata.LastModified = t
		}
	}

	// Extract Vary headers
	if vary := resp.Header.Get(httputil.HeaderVary); vary != "" {
		headers := strings.Split(vary, ",")
		for _, h := range headers {
			h = strings.TrimSpace(h)
			if h != "" {
				metadata.VaryHeaders = append(metadata.VaryHeaders, h)
			}
		}
	}

	// Parse Cache-Control header
	cacheControl := resp.Header.Get(httputil.HeaderCacheControl)
	if cacheControl != "" {
		if err := p.parseCacheControl(cacheControl, metadata); err != nil {
			return nil, fmt.Errorf("failed to parse Cache-Control: %w", err)
		}
	}

	// Parse Expires header as fallback
	if metadata.MaxAge == 0 {
		if expiresStr := resp.Header.Get(httputil.HeaderExpires); expiresStr != "" {
			if dateStr := resp.Header.Get(httputil.HeaderDate); dateStr != "" {
				if date, err := parseHTTPDate(dateStr); err == nil {
					if expires, err := parseHTTPDate(expiresStr); err == nil {
						metadata.MaxAge = expires.Sub(date)
						if metadata.MaxAge < 0 {
							metadata.MaxAge = 0
						}
					}
				}
			}
		}
	}

	// If no cache directives, don't cache
	if metadata.NoStore {
		metadata.ExpiresAt = now.Add(-time.Hour) // Never cache
		metadata.StaleAt = now.Add(-time.Hour)
		metadata.MaxStaleAt = now.Add(-time.Hour)
		return metadata, nil
	}

	// Calculate expiration times
	p.calculateExpiration(metadata, now)

	return metadata, nil
}

// parseCacheControl parses Cache-Control header directives
func (p *HTTPCacheParser) parseCacheControl(cacheControl string, metadata *CacheMetadata) error {
	respDir, err := cacheobject.ParseResponseCacheControl(cacheControl)
	if err != nil {
		return err
	}

	// Parse max-age
	if respDir.MaxAge > 0 {
		metadata.MaxAge = time.Duration(respDir.MaxAge) * time.Second
	}

	// Parse s-maxage (shared cache max-age)
	if respDir.SMaxAge > 0 {
		metadata.MaxAge = time.Duration(respDir.SMaxAge) * time.Second
	}

	// Parse stale-while-revalidate
	if respDir.StaleWhileRevalidate > 0 {
		metadata.StaleWhileRevalidate = time.Duration(respDir.StaleWhileRevalidate) * time.Second
	} else {
		metadata.StaleWhileRevalidate = p.defaultStaleWhileRevalidate
	}

	// Parse stale-if-error (not in cacheobject library, parse manually)
	if staleIfError := p.parseStaleIfError(cacheControl); staleIfError > 0 {
		metadata.StaleIfError = time.Duration(staleIfError) * time.Second
	} else {
		metadata.StaleIfError = p.defaultStaleIfError
	}

	// Parse boolean directives
	metadata.MustRevalidate = respDir.MustRevalidate
	metadata.NoCache = respDir.NoCachePresent
	metadata.NoStore = respDir.NoStore
	metadata.Private = respDir.PrivatePresent
	metadata.Public = respDir.Public

	return nil
}

// parseStaleIfError manually parses stale-if-error directive
func (p *HTTPCacheParser) parseStaleIfError(cacheControl string) int {
	parts := strings.Split(strings.ToLower(cacheControl), ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "stale-if-error=") {
			value := strings.TrimPrefix(part, "stale-if-error=")
			if seconds, err := strconv.Atoi(value); err == nil {
				return seconds
			}
		}
	}
	return 0
}

// calculateExpiration calculates expiration times based on cache metadata
func (p *HTTPCacheParser) calculateExpiration(metadata *CacheMetadata, now time.Time) {
	if metadata.MaxAge <= 0 {
		// Default to 1 hour if no expiration specified
		metadata.MaxAge = time.Hour
	}

	// Fresh until expires
	metadata.ExpiresAt = now.Add(metadata.MaxAge)

	// Stale but usable until stale-while-revalidate expires
	if metadata.StaleWhileRevalidate > 0 {
		metadata.StaleAt = metadata.ExpiresAt.Add(metadata.StaleWhileRevalidate)
	} else {
		metadata.StaleAt = metadata.ExpiresAt
	}

	// Absolute expiry (stale-if-error)
	if metadata.StaleIfError > 0 {
		metadata.MaxStaleAt = metadata.ExpiresAt.Add(metadata.StaleIfError)
	} else {
		metadata.MaxStaleAt = metadata.StaleAt
	}
}

// GetState determines the current state of a cached response
func (m *CacheMetadata) GetState(now time.Time) CacheState {
	if m.NoStore || m.NoCache {
		return StateExpired
	}

	if now.Before(m.ExpiresAt) {
		return StateFresh
	}

	if now.Before(m.StaleAt) {
		return StateStale
	}

	if now.Before(m.MaxStaleAt) {
		return StateStaleError
	}

	return StateExpired
}

// parseHTTPDate parses an HTTP date string (RFC 1123)
func parseHTTPDate(dateStr string) (time.Time, error) {
	// Try RFC 1123 first
	if t, err := time.Parse(time.RFC1123, dateStr); err == nil {
		return t, nil
	}

	// Try RFC 850
	if t, err := time.Parse(time.RFC850, dateStr); err == nil {
		return t, nil
	}

	// Try ANSI C
	if t, err := time.Parse(time.ANSIC, dateStr); err == nil {
		return t, nil
	}

	return time.Time{}, fmt.Errorf("unable to parse date: %s", dateStr)
}

// ShouldCache determines if a response should be cached based on HTTP headers
func (p *HTTPCacheParser) ShouldCache(metadata *CacheMetadata) bool {
	if metadata.NoStore {
		slog.Debug("response should not be cached: no-store directive")
		return false
	}

	if metadata.NoCache && metadata.MustRevalidate {
		slog.Debug("response should not be cached: no-cache with must-revalidate")
		return false
	}

	return true
}
