// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import "strconv"

// PromptCacheConfig configures provider prompt caching behavior.
type PromptCacheConfig struct {
	Enabled bool `json:"enabled,omitempty" yaml:"enabled"`
}

// InjectCacheHeaders adds provider-specific cache control headers to the outbound request.
// For Anthropic: adds the prompt-caching beta header.
// For OpenAI: prompt caching is automatic (no extra headers needed).
func InjectCacheHeaders(provider string, headers map[string]string) {
	switch provider {
	case "anthropic":
		headers["anthropic-beta"] = "prompt-caching-2024-07-31"
	}
	// OpenAI enables prompt caching automatically for supported models.
	// Other providers do not currently support prompt caching headers.
}

// ParseCacheMetrics extracts cache hit/miss token counts from provider response headers.
// Returns the number of tokens written to cache (cacheCreated) and read from cache (cacheRead).
func ParseCacheMetrics(provider string, headers map[string]string) (cacheCreated, cacheRead int) {
	switch provider {
	case "anthropic":
		// Anthropic returns cache metrics in response headers.
		if v, ok := headers["anthropic-cache-creation-input-tokens"]; ok {
			cacheCreated, _ = strconv.Atoi(v)
		}
		if v, ok := headers["anthropic-cache-read-input-tokens"]; ok {
			cacheRead, _ = strconv.Atoi(v)
		}
	case "openai":
		// OpenAI returns cache metrics in the usage object, not headers.
		// The caller should check the response body usage.prompt_tokens_details.cached_tokens field.
		if v, ok := headers["x-cache-creation-tokens"]; ok {
			cacheCreated, _ = strconv.Atoi(v)
		}
		if v, ok := headers["x-cache-read-tokens"]; ok {
			cacheRead, _ = strconv.Atoi(v)
		}
	}
	return cacheCreated, cacheRead
}
