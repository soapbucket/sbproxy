// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"net/http"
	"strconv"
	"time"
)

// RateLimitInfo holds rate limit state for standardized header generation.
// This is populated by the rate limiting policy and read during response processing.
type RateLimitInfo struct {
	Limit     int       // Total requests allowed in the window
	Remaining int       // Requests remaining in the current window
	Reset     time.Time // When the current window resets
}

// applyRateLimitHeaders adds standardized rate limit headers per
// draft-ietf-httpapi-ratelimit-headers.
func applyRateLimitHeaders(w http.ResponseWriter, info *RateLimitInfo, cfg *RateLimitHeaderConfig) {
	if cfg == nil || !cfg.Enable || info == nil {
		return
	}

	w.Header().Set("RateLimit-Limit", strconv.Itoa(info.Limit))
	w.Header().Set("RateLimit-Remaining", strconv.Itoa(info.Remaining))

	// Reset as seconds until window resets (delta-seconds)
	remaining := time.Until(info.Reset)
	if remaining < 0 {
		remaining = 0
	}
	w.Header().Set("RateLimit-Reset", strconv.Itoa(int(remaining.Seconds())))
}

// applyRetryAfterHeader adds the Retry-After header on 429 responses.
func applyRetryAfterHeader(w http.ResponseWriter, info *RateLimitInfo) {
	if info == nil {
		return
	}

	remaining := time.Until(info.Reset)
	if remaining < 0 {
		remaining = time.Second
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(remaining.Seconds())+1))
}
