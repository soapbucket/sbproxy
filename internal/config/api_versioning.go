// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"net/http"
	"strings"
)

// VersionExtractor extracts the API version from an incoming request.
type VersionExtractor struct {
	config   *APIVersionConfig
	versions map[string]*APIVersion // name -> version for O(1) lookup
}

// NewVersionExtractor creates a VersionExtractor from the given config.
// It builds an internal lookup map keyed by version name for fast extraction.
func NewVersionExtractor(cfg *APIVersionConfig) *VersionExtractor {
	if cfg == nil {
		return nil
	}
	ve := &VersionExtractor{
		config:   cfg,
		versions: make(map[string]*APIVersion, len(cfg.Versions)),
	}
	for i := range cfg.Versions {
		ve.versions[cfg.Versions[i].Name] = &cfg.Versions[i]
	}
	return ve
}

// Extract returns the matched API version from the request based on the
// configured location (header, url, query). If no version is found but a
// default is configured, the default version is returned. The second return
// value indicates whether a version was resolved at all.
func (ve *VersionExtractor) Extract(r *http.Request) (version *APIVersion, found bool) {
	if ve == nil || ve.config == nil {
		return nil, false
	}

	var name string

	switch ve.config.Location {
	case "header":
		key := ve.config.Key
		if key == "" {
			key = "X-API-Version"
		}
		name = r.Header.Get(key)

	case "url":
		// Match the request path against each version's URLPrefix.
		for i := range ve.config.Versions {
			v := &ve.config.Versions[i]
			if v.URLPrefix != "" && strings.HasPrefix(r.URL.Path, v.URLPrefix) {
				// Ensure the prefix is a proper segment boundary: either the
				// path equals the prefix exactly, or the next character is '/'.
				if len(r.URL.Path) == len(v.URLPrefix) || r.URL.Path[len(v.URLPrefix)] == '/' {
					return v, true
				}
			}
		}

	case "query":
		key := ve.config.Key
		if key == "" {
			key = "version"
		}
		name = r.URL.Query().Get(key)
	}

	if name != "" {
		if v, ok := ve.versions[name]; ok {
			return v, true
		}
	}

	// Fall back to default version.
	if ve.config.DefaultVersion != "" {
		if v, ok := ve.versions[ve.config.DefaultVersion]; ok {
			return v, true
		}
	}

	return nil, false
}

// Middleware returns an http.Handler that performs API version extraction,
// adds deprecation/sunset response headers, strips URL prefixes, and rewrites
// upstream paths before forwarding to the next handler.
func (ve *VersionExtractor) Middleware(next http.Handler) http.Handler {
	if ve == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		version, found := ve.Extract(r)
		if !found {
			next.ServeHTTP(w, r)
			return
		}

		// Add deprecation headers per RFC 8594.
		if version.Deprecated {
			w.Header().Set("Deprecation", "true")
			if version.SunsetDate != "" {
				w.Header().Set("Sunset", version.SunsetDate)
			}
		}

		// Strip version prefix from path if configured.
		if version.StripVersion && version.URLPrefix != "" {
			trimmed := strings.TrimPrefix(r.URL.Path, version.URLPrefix)
			if trimmed == "" {
				trimmed = "/"
			}
			r.URL.Path = trimmed
			// Also update RawPath when present so encoded segments stay consistent.
			if r.URL.RawPath != "" {
				r.URL.RawPath = strings.TrimPrefix(r.URL.RawPath, version.URLPrefix)
				if r.URL.RawPath == "" {
					r.URL.RawPath = "/"
				}
			}
		}

		// Override upstream path if the version specifies one.
		if version.UpstreamPath != "" {
			// Preserve any remaining suffix after the version prefix was stripped.
			suffix := r.URL.Path
			r.URL.Path = strings.TrimSuffix(version.UpstreamPath, "/") + suffix
		}

		// Propagate the resolved version name to upstream via header.
		r.Header.Set("X-API-Version", version.Name)

		next.ServeHTTP(w, r)
	})
}
