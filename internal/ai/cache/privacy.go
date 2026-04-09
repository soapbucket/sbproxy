// Package cache implements semantic caching for AI responses using vector similarity search.
package cache

import "net/http"

// PrivacyLevel controls what cache data is stored.
type PrivacyLevel string

const (
	// PrivacyFull stores full request/response content in cache.
	PrivacyFull PrivacyLevel = "full"
	// PrivacyMetrics stores only metrics (hit/miss counts, token usage) but no content.
	PrivacyMetrics PrivacyLevel = "metrics"
	// PrivacyNone disables all caching and metrics collection.
	PrivacyNone PrivacyLevel = "none"
)

// privacyRank maps privacy levels to their restrictiveness (higher is more restrictive).
var privacyRank = map[PrivacyLevel]int{
	PrivacyFull:    0,
	PrivacyMetrics: 1,
	PrivacyNone:    2,
}

// PrivacyConfig configures cache privacy controls.
type PrivacyConfig struct {
	// DefaultLevel is the default privacy level for all requests.
	DefaultLevel PrivacyLevel `json:"default_level,omitempty"`
	// HeaderOverride allows per-request privacy level via header.
	// The header value overrides the default only if more restrictive.
	// Defaults to "X-SB-Cache-Privacy" when empty.
	HeaderOverride string `json:"header_override,omitempty"`
	// PolicyLevel allows policy-level privacy settings.
	// Policy is always the most restrictive when set.
	PolicyLevel PrivacyLevel `json:"policy_level,omitempty"`
}

// PrivacyGuard enforces privacy levels for cache operations.
type PrivacyGuard struct {
	config *PrivacyConfig
}

// NewPrivacyGuard creates a new privacy guard with the given configuration.
// If cfg is nil, defaults to PrivacyFull with standard header override.
func NewPrivacyGuard(cfg *PrivacyConfig) *PrivacyGuard {
	if cfg == nil {
		cfg = &PrivacyConfig{
			DefaultLevel: PrivacyFull,
		}
	}
	if cfg.DefaultLevel == "" {
		cfg.DefaultLevel = PrivacyFull
	}
	return &PrivacyGuard{config: cfg}
}

// ResolveLevel determines the effective privacy level for a request.
// It applies the following precedence (most restrictive wins at each step):
//  1. Start with the configured default level.
//  2. If a request header override is present, take the more restrictive of the two.
//  3. If a policy level is set, take the more restrictive of the result and the policy.
func (pg *PrivacyGuard) ResolveLevel(r *http.Request) PrivacyLevel {
	level := pg.config.DefaultLevel

	// Check header override.
	if r != nil {
		headerName := pg.config.HeaderOverride
		if headerName == "" {
			headerName = "X-SB-Cache-Privacy"
		}
		if headerVal := r.Header.Get(headerName); headerVal != "" {
			headerLevel := PrivacyLevel(headerVal)
			if isValidPrivacyLevel(headerLevel) {
				level = moreRestrictive(level, headerLevel)
			}
		}
	}

	// Policy override always wins (most restrictive).
	if pg.config.PolicyLevel != "" && isValidPrivacyLevel(pg.config.PolicyLevel) {
		level = moreRestrictive(level, pg.config.PolicyLevel)
	}

	return level
}

// AllowCache returns true if caching is allowed at the given privacy level.
// Caching is allowed for "full" and "metrics" levels but not "none".
func AllowCache(level PrivacyLevel) bool {
	return level != PrivacyNone
}

// AllowMetrics returns true if metrics collection is allowed at the given privacy level.
// Metrics are allowed for "full" and "metrics" levels but not "none".
func AllowMetrics(level PrivacyLevel) bool {
	return level != PrivacyNone
}

// AllowContent returns true if content storage is allowed at the given privacy level.
// Content storage is only allowed at the "full" level.
func AllowContent(level PrivacyLevel) bool {
	return level == PrivacyFull
}

// moreRestrictive returns the more restrictive of two privacy levels.
// Privacy level ordering (most to least restrictive): none > metrics > full.
func moreRestrictive(a, b PrivacyLevel) PrivacyLevel {
	rankA := privacyRank[a]
	rankB := privacyRank[b]
	if rankA >= rankB {
		return a
	}
	return b
}

// isValidPrivacyLevel checks if the given level is a recognized privacy level.
func isValidPrivacyLevel(level PrivacyLevel) bool {
	_, ok := privacyRank[level]
	return ok
}
