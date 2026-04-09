package ai

import (
	"testing"

	json "github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPromptCacheCacheControlMarshal(t *testing.T) {
	part := ContentPart{
		Type: "text",
		Text: "Hello, world!",
		CacheControl: &CacheControlConfig{
			Type: "ephemeral",
		},
	}

	data, err := json.Marshal(part)
	require.NoError(t, err)

	var decoded ContentPart
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "text", decoded.Type)
	assert.Equal(t, "Hello, world!", decoded.Text)
	require.NotNil(t, decoded.CacheControl)
	assert.Equal(t, "ephemeral", decoded.CacheControl.Type)
}

func TestPromptCacheCacheControlOmittedWhenNil(t *testing.T) {
	part := ContentPart{
		Type: "text",
		Text: "No cache",
	}

	data, err := json.Marshal(part)
	require.NoError(t, err)

	// cache_control should not appear in JSON
	var raw map[string]any
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)
	_, hasCacheControl := raw["cache_control"]
	assert.False(t, hasCacheControl, "cache_control should be omitted when nil")
}

func TestPromptCacheUsageCacheTokenTracking(t *testing.T) {
	usage := Usage{
		PromptTokens:             1000,
		CompletionTokens:         500,
		TotalTokens:              1500,
		CacheCreationInputTokens: 800,
		CacheReadInputTokens:     200,
		PromptTokensDetails: &PromptTokensDetails{
			CachedTokens: 200,
		},
	}

	data, err := json.Marshal(usage)
	require.NoError(t, err)

	var decoded Usage
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, 800, decoded.CacheCreationInputTokens)
	assert.Equal(t, 200, decoded.CacheReadInputTokens)
	require.NotNil(t, decoded.PromptTokensDetails)
	assert.Equal(t, 200, decoded.PromptTokensDetails.CachedTokens)
}

func TestPromptCacheNonCachingRequestHasZeroCacheTokens(t *testing.T) {
	usage := Usage{
		PromptTokens:     500,
		CompletionTokens: 200,
		TotalTokens:      700,
	}

	assert.Equal(t, 0, usage.CacheCreationInputTokens)
	assert.Equal(t, 0, usage.CacheReadInputTokens)
	assert.Nil(t, usage.PromptTokensDetails)

	// Verify omitempty removes cache fields from JSON
	data, err := json.Marshal(usage)
	require.NoError(t, err)

	var raw map[string]any
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	_, hasCreation := raw["cache_creation_input_tokens"]
	_, hasRead := raw["cache_read_input_tokens"]
	_, hasDetails := raw["prompt_tokens_details"]
	assert.False(t, hasCreation, "cache_creation_input_tokens should be omitted when zero")
	assert.False(t, hasRead, "cache_read_input_tokens should be omitted when zero")
	assert.False(t, hasDetails, "prompt_tokens_details should be omitted when nil")
}

func TestPromptCacheUnmarshalFromProvider(t *testing.T) {
	// Simulate an Anthropic-style usage response with cache tokens
	raw := `{
		"prompt_tokens": 1500,
		"completion_tokens": 300,
		"total_tokens": 1800,
		"cache_creation_input_tokens": 1000,
		"cache_read_input_tokens": 500,
		"prompt_tokens_details": {
			"cached_tokens": 500
		}
	}`

	var usage Usage
	err := json.Unmarshal([]byte(raw), &usage)
	require.NoError(t, err)

	assert.Equal(t, 1500, usage.PromptTokens)
	assert.Equal(t, 1000, usage.CacheCreationInputTokens)
	assert.Equal(t, 500, usage.CacheReadInputTokens)
	require.NotNil(t, usage.PromptTokensDetails)
	assert.Equal(t, 500, usage.PromptTokensDetails.CachedTokens)
}
