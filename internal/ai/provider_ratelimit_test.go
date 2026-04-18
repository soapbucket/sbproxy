package ai

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProviderRateLimitTracker_ParseHeaders_OpenAI(t *testing.T) {
	tracker := NewProviderRateLimitTracker()

	headers := http.Header{}
	headers.Set("x-ratelimit-remaining-requests", "95")
	headers.Set("x-ratelimit-limit-requests", "100")
	headers.Set("x-ratelimit-remaining-tokens", "45000")
	headers.Set("x-ratelimit-limit-tokens", "50000")

	tracker.ParseHeaders("openai", headers)

	rl := tracker.GetLimits("openai")
	require.NotNil(t, rl)
	assert.Equal(t, 95, rl.RequestsRemaining)
	assert.Equal(t, 100, rl.RequestsLimit)
	assert.Equal(t, 45000, rl.TokensRemaining)
	assert.Equal(t, 50000, rl.TokensLimit)
}

func TestProviderRateLimitTracker_ParseHeaders_Anthropic(t *testing.T) {
	tracker := NewProviderRateLimitTracker()

	headers := http.Header{}
	headers.Set("anthropic-ratelimit-requests-remaining", "10")
	headers.Set("anthropic-ratelimit-requests-limit", "60")
	headers.Set("anthropic-ratelimit-tokens-remaining", "8000")
	headers.Set("anthropic-ratelimit-tokens-limit", "100000")

	tracker.ParseHeaders("anthropic", headers)

	rl := tracker.GetLimits("anthropic")
	require.NotNil(t, rl)
	assert.Equal(t, 10, rl.RequestsRemaining)
	assert.Equal(t, 60, rl.RequestsLimit)
	assert.Equal(t, 8000, rl.TokensRemaining)
	assert.Equal(t, 100000, rl.TokensLimit)
}

func TestProviderRateLimitTracker_ParseHeaders_RetryAfter(t *testing.T) {
	tracker := NewProviderRateLimitTracker()

	headers := http.Header{}
	headers.Set("Retry-After", "30")

	tracker.ParseHeaders("openai", headers)

	rl := tracker.GetLimits("openai")
	require.NotNil(t, rl)
	assert.Equal(t, 30, int(rl.RetryAfter.Seconds()))
}

func TestProviderRateLimitTracker_ShouldThrottle_LowRequests(t *testing.T) {
	tracker := NewProviderRateLimitTracker()

	headers := http.Header{}
	headers.Set("x-ratelimit-remaining-requests", "2")
	headers.Set("x-ratelimit-limit-requests", "100")
	headers.Set("x-ratelimit-remaining-tokens", "50000")
	headers.Set("x-ratelimit-limit-tokens", "50000")

	tracker.ParseHeaders("openai", headers)
	assert.True(t, tracker.ShouldThrottle("openai"))
}

func TestProviderRateLimitTracker_ShouldThrottle_LowTokens(t *testing.T) {
	tracker := NewProviderRateLimitTracker()

	headers := http.Header{}
	headers.Set("x-ratelimit-remaining-requests", "50")
	headers.Set("x-ratelimit-limit-requests", "100")
	headers.Set("x-ratelimit-remaining-tokens", "100")
	headers.Set("x-ratelimit-limit-tokens", "50000")

	tracker.ParseHeaders("openai", headers)
	assert.True(t, tracker.ShouldThrottle("openai"))
}

func TestProviderRateLimitTracker_ShouldThrottle_Healthy(t *testing.T) {
	tracker := NewProviderRateLimitTracker()

	headers := http.Header{}
	headers.Set("x-ratelimit-remaining-requests", "80")
	headers.Set("x-ratelimit-limit-requests", "100")
	headers.Set("x-ratelimit-remaining-tokens", "40000")
	headers.Set("x-ratelimit-limit-tokens", "50000")

	tracker.ParseHeaders("openai", headers)
	assert.False(t, tracker.ShouldThrottle("openai"))
}

func TestProviderRateLimitTracker_ShouldThrottle_UnknownProvider(t *testing.T) {
	tracker := NewProviderRateLimitTracker()
	assert.False(t, tracker.ShouldThrottle("unknown"))
}

func TestProviderRateLimitTracker_GetLimits_Unknown(t *testing.T) {
	tracker := NewProviderRateLimitTracker()
	assert.Nil(t, tracker.GetLimits("nonexistent"))
}

func TestProviderRateLimitTracker_GetLimits_ReturnsCopy(t *testing.T) {
	tracker := NewProviderRateLimitTracker()

	headers := http.Header{}
	headers.Set("x-ratelimit-remaining-requests", "50")
	headers.Set("x-ratelimit-limit-requests", "100")
	tracker.ParseHeaders("openai", headers)

	rl1 := tracker.GetLimits("openai")
	rl1.RequestsRemaining = 999

	rl2 := tracker.GetLimits("openai")
	assert.Equal(t, 50, rl2.RequestsRemaining, "modifying returned value should not affect tracker")
}
