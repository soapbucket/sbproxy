// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"fmt"
	"net/http"
	"strings"
)

// applyHSTSHeader adds the Strict-Transport-Security header per RFC 6797.
// Only applied to HTTPS responses. Uses the existing HSTSConfig from types.go.
func applyHSTSHeader(resp *http.Response, req *http.Request, cfg *HSTSConfig) {
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
