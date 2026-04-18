// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

// ModelContextLimits maps model IDs to their maximum context window sizes (in tokens).
var ModelContextLimits = map[string]int{
	"gpt-4o":                      128000,
	"gpt-4o-mini":                 128000,
	"gpt-4-turbo":                 128000,
	"gpt-4":                       8192,
	"gpt-3.5-turbo":               16385,
	"claude-sonnet-4-20250514":    200000,
	"claude-3-5-sonnet-20241022":  200000,
	"claude-3-haiku-20240307":     200000,
	"gemini-1.5-pro":              2000000,
	"gemini-1.5-flash":            1000000,
	"gemini-2.0-flash":            1000000,
}

// CheckContextOverflow estimates whether a request will exceed the model's context window.
// Returns the estimated token count, the model's max context window, and whether it overflows.
// If the model is not in the known limits map, overflow is always false.
func CheckContextOverflow(model string, estimatedTokens int) (estimated, max int, overflow bool) {
	max, ok := ModelContextLimits[model]
	if !ok {
		return estimatedTokens, 0, false
	}
	return estimatedTokens, max, estimatedTokens > max
}

// SuggestFallbackModel returns a model with a larger context window that can accommodate
// the needed token count. It searches across all known models for the smallest context
// window that still fits. Returns the model name and true if found, or empty string and false.
func SuggestFallbackModel(currentModel string, neededTokens int) (string, bool) {
	currentMax, currentKnown := ModelContextLimits[currentModel]
	if currentKnown && neededTokens <= currentMax {
		return currentModel, true
	}

	bestModel := ""
	bestMax := 0

	for model, limit := range ModelContextLimits {
		if model == currentModel {
			continue
		}
		if limit < neededTokens {
			continue
		}
		// Pick the smallest sufficient context window to avoid unnecessary upgrades.
		if bestModel == "" || limit < bestMax {
			bestModel = model
			bestMax = limit
		}
	}

	if bestModel != "" {
		return bestModel, true
	}
	return "", false
}
