// Package limits provides rate limiting and concurrency control for AI requests.
package limits

import (
	"context"
	"fmt"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/request/ratelimit"
)

// ModelRateConfig holds rate limit configuration for a single model.
type ModelRateConfig struct {
	RPM int `json:"rpm"` // Requests per minute
	TPM int `json:"tpm"` // Tokens per minute
}

// ModelRateLimiter enforces per-model rate limits using distributed counters.
type ModelRateLimiter struct {
	limiter ratelimit.RateLimiter
	configs map[string]ModelRateConfig // key: "provider:model"
}

// NewModelRateLimiter creates a rate limiter backed by the given cache.
func NewModelRateLimiter(cache cacher.Cacher) *ModelRateLimiter {
	return &ModelRateLimiter{
		limiter: ratelimit.NewDistributedRateLimiter(cache, "ai:rl:model"),
		configs: make(map[string]ModelRateConfig),
	}
}

// Configure sets rate limits for a provider:model pair.
func (l *ModelRateLimiter) Configure(provider, model string, cfg ModelRateConfig) {
	l.configs[provider+":"+model] = cfg
}

// AllowRequest checks if an RPM-based request is allowed for the given
// provider and model combination. Returns an allowed result when no
// configuration exists for the model.
func (l *ModelRateLimiter) AllowRequest(ctx context.Context, provider, model string) (ratelimit.Result, error) {
	key := provider + ":" + model
	cfg, ok := l.configs[key]
	if !ok || cfg.RPM == 0 {
		return ratelimit.Result{Allowed: true}, nil
	}
	return l.limiter.Allow(ctx, key+":rpm", cfg.RPM, time.Minute)
}

// AllowRequestWithFlags checks if an RPM-based request is allowed, with
// optional feature flag override. If the flag "ai.models.<model>.rpm_limit"
// exists in the provided flags map and is a positive number, it overrides
// the configured RPM for this check.
func (l *ModelRateLimiter) AllowRequestWithFlags(ctx context.Context, provider, model string, flags map[string]interface{}) (ratelimit.Result, error) {
	key := provider + ":" + model
	cfg, ok := l.configs[key]
	if !ok {
		cfg = ModelRateConfig{} // No base config
	}

	// Check feature flag override.
	flagKey := fmt.Sprintf("ai.models.%s.rpm_limit", model)
	if flags != nil {
		if val, exists := flags[flagKey]; exists {
			if rpm, ok := val.(float64); ok && rpm > 0 {
				cfg.RPM = int(rpm)
			}
		}
	}

	if cfg.RPM == 0 {
		return ratelimit.Result{Allowed: true}, nil
	}
	return l.limiter.Allow(ctx, key+":rpm", cfg.RPM, time.Minute)
}

// AllowTokens checks if a TPM-based token count is allowed for the given
// provider and model combination. Returns an allowed result when no
// configuration exists for the model.
func (l *ModelRateLimiter) AllowTokens(ctx context.Context, provider, model string, tokens int) (ratelimit.Result, error) {
	key := provider + ":" + model
	cfg, ok := l.configs[key]
	if !ok || cfg.TPM == 0 {
		return ratelimit.Result{Allowed: true}, nil
	}
	return l.limiter.AllowN(ctx, key+":tpm", tokens, cfg.TPM, time.Minute)
}
