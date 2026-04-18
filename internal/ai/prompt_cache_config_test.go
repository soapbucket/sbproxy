package ai

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInjectCacheHeaders_Anthropic(t *testing.T) {
	headers := make(map[string]string)
	InjectCacheHeaders("anthropic", headers)
	assert.Equal(t, "prompt-caching-2024-07-31", headers["anthropic-beta"])
}

func TestInjectCacheHeaders_OpenAI(t *testing.T) {
	headers := make(map[string]string)
	InjectCacheHeaders("openai", headers)
	// OpenAI does not require extra headers for prompt caching.
	assert.Empty(t, headers)
}

func TestInjectCacheHeaders_UnknownProvider(t *testing.T) {
	headers := make(map[string]string)
	InjectCacheHeaders("unknown", headers)
	assert.Empty(t, headers)
}

func TestParseCacheMetrics_Anthropic(t *testing.T) {
	headers := map[string]string{
		"anthropic-cache-creation-input-tokens": "1500",
		"anthropic-cache-read-input-tokens":     "3000",
	}
	created, read := ParseCacheMetrics("anthropic", headers)
	assert.Equal(t, 1500, created)
	assert.Equal(t, 3000, read)
}

func TestParseCacheMetrics_Anthropic_MissingHeaders(t *testing.T) {
	headers := map[string]string{}
	created, read := ParseCacheMetrics("anthropic", headers)
	assert.Equal(t, 0, created)
	assert.Equal(t, 0, read)
}

func TestParseCacheMetrics_OpenAI(t *testing.T) {
	headers := map[string]string{
		"x-cache-creation-tokens": "500",
		"x-cache-read-tokens":     "1000",
	}
	created, read := ParseCacheMetrics("openai", headers)
	assert.Equal(t, 500, created)
	assert.Equal(t, 1000, read)
}

func TestParseCacheMetrics_UnknownProvider(t *testing.T) {
	headers := map[string]string{
		"anthropic-cache-creation-input-tokens": "1500",
	}
	created, read := ParseCacheMetrics("unknown", headers)
	assert.Equal(t, 0, created)
	assert.Equal(t, 0, read)
}

func TestPromptCacheConfig_Defaults(t *testing.T) {
	cfg := PromptCacheConfig{}
	assert.False(t, cfg.Enabled)

	cfg.Enabled = true
	assert.True(t, cfg.Enabled)
}
