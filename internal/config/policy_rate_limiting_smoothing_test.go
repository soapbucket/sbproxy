package config

import (
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/stretchr/testify/assert"
)

func TestSmoothedLimit(t *testing.T) {
	p := &RateLimitingPolicyConfig{
		RateLimitingPolicy: RateLimitingPolicy{
			Smoothing: &SmoothingConfig{
				RampDuration: reqctx.Duration{Duration: time.Hour},
				InitialRate:  0.1,
			},
		},
		counters: make(map[string]*rateLimitCounters),
	}

	// New consumer with no history
	result := p.smoothedLimit(100, nil)
	assert.Equal(t, 100, result) // nil counters returns base

	// Brand new consumer
	counters := &rateLimitCounters{firstSeen: time.Now()}
	result = p.smoothedLimit(100, counters)
	assert.True(t, result >= 10 && result <= 15, "expected ~10, got %d", result)

	// Consumer at 50% ramp
	counters = &rateLimitCounters{firstSeen: time.Now().Add(-30 * time.Minute)}
	result = p.smoothedLimit(100, counters)
	assert.True(t, result >= 50 && result <= 60, "expected ~55, got %d", result)

	// Consumer past ramp duration
	counters = &rateLimitCounters{firstSeen: time.Now().Add(-2 * time.Hour)}
	result = p.smoothedLimit(100, counters)
	assert.Equal(t, 100, result)
}

func TestSmoothedLimitDisabled(t *testing.T) {
	p := &RateLimitingPolicyConfig{
		counters: make(map[string]*rateLimitCounters),
	}

	counters := &rateLimitCounters{firstSeen: time.Now()}
	result := p.smoothedLimit(100, counters)
	assert.Equal(t, 100, result) // No smoothing config, return base
}

func TestSmoothedLimitMinimum(t *testing.T) {
	p := &RateLimitingPolicyConfig{
		RateLimitingPolicy: RateLimitingPolicy{
			Smoothing: &SmoothingConfig{
				RampDuration: reqctx.Duration{Duration: time.Hour},
				InitialRate:  0.001,
			},
		},
		counters: make(map[string]*rateLimitCounters),
	}

	// Even with very low initial rate, minimum is 1
	counters := &rateLimitCounters{firstSeen: time.Now()}
	result := p.smoothedLimit(5, counters)
	assert.True(t, result >= 1, "minimum should be 1, got %d", result)
}
