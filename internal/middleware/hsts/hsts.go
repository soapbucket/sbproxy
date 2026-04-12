// Package hsts implements HTTP Strict Transport Security (RFC 6797) header injection.
package hsts

import (
	"fmt"
	"net/http"
	"strings"
)

// Config holds configuration for HSTS.
type Config struct {
	Enabled           bool `json:"enabled,omitempty"`
	MaxAge            int  `json:"max_age,omitempty"` // in seconds
	IncludeSubdomains bool `json:"include_subdomains,omitempty"`
	Preload           bool `json:"preload,omitempty"`
}

// ApplyHeader adds the Strict-Transport-Security header per RFC 6797.
// Only applied to HTTPS responses.
func ApplyHeader(resp *http.Response, req *http.Request, cfg *Config) {
	if cfg == nil || !cfg.Enabled {
		return
	}

	// Only add HSTS on HTTPS responses
	if req == nil || req.TLS == nil {
		return
	}

	maxAge := cfg.MaxAge
	if maxAge <= 0 {
		maxAge = 31536000 // 1 year
	}

	var b strings.Builder
	b.Grow(64)
	fmt.Fprintf(&b, "max-age=%d", maxAge)

	if cfg.IncludeSubdomains {
		b.WriteString("; includeSubDomains")
	}

	if cfg.Preload {
		b.WriteString("; preload")
	}

	resp.Header.Set("Strict-Transport-Security", b.String())
}
