// Package httputil defines HTTP constants, header names, and shared request/response utilities.
package httputil

import (
	"time"
)

// CachedResponse represents a cached HTTP response with metadata
type CachedResponse struct {
	// Cache metadata
	Expires       time.Time     `json:"expires"`        // When the cache entry expires
	StaleDuration time.Duration `json:"stale_duration"` // How long to serve stale content
	ETag          string        `json:"etag"`           // ETag for validation
	LastModified  time.Time     `json:"last_modified"`  // Last-Modified timestamp

	// Cache control directives
	MaxAge         int  `json:"max_age"`         // Max age in seconds
	MustRevalidate bool `json:"must_revalidate"` // Must revalidate directive
	NoCache        bool `json:"no_cache"`        // No-cache directive
	NoStore        bool `json:"no_store"`        // No-store directive
	Private        bool `json:"private"`         // Private directive
	Public         bool `json:"public"`          // Public directive

	// Vary headers that affect cache key
	VaryHeaders []string `json:"vary_headers"`

	// Response metadata
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Size       int64             `json:"size"`
}
