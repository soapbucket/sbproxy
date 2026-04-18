// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"net/http"
	"strconv"
	"sync"
	"time"
)

// ProviderRateLimitTracker tracks rate limit headers from provider responses.
// It parses standard and provider-specific rate limit headers so the gateway
// can pre-emptively back off before hitting hard limits.
type ProviderRateLimitTracker struct {
	mu     sync.RWMutex
	limits map[string]*ProviderRateLimit // provider name -> rate limit state
}

// ProviderRateLimit holds the parsed rate limit state for a provider.
type ProviderRateLimit struct {
	RequestsRemaining int
	RequestsLimit     int
	TokensRemaining   int
	TokensLimit       int
	ResetAt           time.Time
	RetryAfter        time.Duration
}

// NewProviderRateLimitTracker creates a new tracker.
func NewProviderRateLimitTracker() *ProviderRateLimitTracker {
	return &ProviderRateLimitTracker{
		limits: make(map[string]*ProviderRateLimit),
	}
}

// ParseHeaders extracts rate limit information from provider response headers.
// Supports OpenAI (x-ratelimit-*), Anthropic (anthropic-ratelimit-*),
// and standard x-ratelimit-* header patterns.
func (t *ProviderRateLimitTracker) ParseHeaders(provider string, headers http.Header) {
	rl := &ProviderRateLimit{}

	// OpenAI / standard headers
	if v := headers.Get("x-ratelimit-remaining-requests"); v != "" {
		rl.RequestsRemaining, _ = strconv.Atoi(v)
	}
	if v := headers.Get("x-ratelimit-limit-requests"); v != "" {
		rl.RequestsLimit, _ = strconv.Atoi(v)
	}
	if v := headers.Get("x-ratelimit-remaining-tokens"); v != "" {
		rl.TokensRemaining, _ = strconv.Atoi(v)
	}
	if v := headers.Get("x-ratelimit-limit-tokens"); v != "" {
		rl.TokensLimit, _ = strconv.Atoi(v)
	}
	if v := headers.Get("x-ratelimit-reset-requests"); v != "" {
		rl.ResetAt = parseResetTime(v)
	}

	// Anthropic-specific headers
	if v := headers.Get("anthropic-ratelimit-requests-remaining"); v != "" {
		rl.RequestsRemaining, _ = strconv.Atoi(v)
	}
	if v := headers.Get("anthropic-ratelimit-requests-limit"); v != "" {
		rl.RequestsLimit, _ = strconv.Atoi(v)
	}
	if v := headers.Get("anthropic-ratelimit-tokens-remaining"); v != "" {
		rl.TokensRemaining, _ = strconv.Atoi(v)
	}
	if v := headers.Get("anthropic-ratelimit-tokens-limit"); v != "" {
		rl.TokensLimit, _ = strconv.Atoi(v)
	}
	if v := headers.Get("anthropic-ratelimit-requests-reset"); v != "" {
		rl.ResetAt = parseResetTime(v)
	}

	// Standard Retry-After header (seconds or HTTP-date)
	if v := headers.Get("Retry-After"); v != "" {
		if seconds, err := strconv.Atoi(v); err == nil {
			rl.RetryAfter = time.Duration(seconds) * time.Second
		} else if t, err := http.ParseTime(v); err == nil {
			rl.RetryAfter = time.Until(t)
			if rl.RetryAfter < 0 {
				rl.RetryAfter = 0
			}
		}
	}

	t.mu.Lock()
	t.limits[provider] = rl
	t.mu.Unlock()
}

// ShouldThrottle returns true if we should pre-emptively back off for a provider.
// Throttling triggers when remaining requests or tokens drop below 5% of the limit,
// or when a Retry-After period has not yet elapsed.
func (t *ProviderRateLimitTracker) ShouldThrottle(provider string) bool {
	t.mu.RLock()
	rl, ok := t.limits[provider]
	t.mu.RUnlock()
	if !ok {
		return false
	}

	// Retry-After still active
	if rl.RetryAfter > 0 && !rl.ResetAt.IsZero() && time.Now().Before(rl.ResetAt.Add(rl.RetryAfter)) {
		return true
	}

	// Request-based throttle: remaining < 5% of limit
	if rl.RequestsLimit > 0 && rl.RequestsRemaining > 0 {
		threshold := rl.RequestsLimit / 20 // 5%
		if threshold < 1 {
			threshold = 1
		}
		if rl.RequestsRemaining <= threshold {
			return true
		}
	}

	// Token-based throttle: remaining < 5% of limit
	if rl.TokensLimit > 0 && rl.TokensRemaining > 0 {
		threshold := rl.TokensLimit / 20 // 5%
		if threshold < 1 {
			threshold = 1
		}
		if rl.TokensRemaining <= threshold {
			return true
		}
	}

	return false
}

// GetLimits returns the current rate limit state for a provider, or nil if unknown.
func (t *ProviderRateLimitTracker) GetLimits(provider string) *ProviderRateLimit {
	t.mu.RLock()
	defer t.mu.RUnlock()
	rl, ok := t.limits[provider]
	if !ok {
		return nil
	}
	// Return a copy to avoid data races.
	cp := *rl
	return &cp
}

// parseResetTime attempts to parse a reset time value as either a duration string
// (e.g., "30s", "1m") or an RFC3339 timestamp.
func parseResetTime(v string) time.Time {
	// Try as duration first (e.g., "6m0s")
	if d, err := time.ParseDuration(v); err == nil {
		return time.Now().Add(d)
	}
	// Try as RFC3339 timestamp
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t
	}
	return time.Time{}
}
