// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

// paramSupport defines which optional parameters a provider does NOT support.
// Parameters listed here will be stripped from the request before forwarding.
// OpenAI supports everything so it has no entries.
var paramSupport = map[string]map[string]bool{
	"openai":  {},
	"generic": {},
	"anthropic": {
		"logit_bias":        true,
		"n":                 true,
		"presence_penalty":  true,
		"frequency_penalty": true,
	},
	"bedrock": {
		"logit_bias": true,
		"n":          true,
	},
	"gemini": {
		"logit_bias": true,
		"n":          true,
	},
	"ollama": {
		"logit_bias": true,
		"seed":       true,
	},
	"azure": {
		"logit_bias": true,
	},
	"groq": {
		"logit_bias": true,
		"n":          true,
	},
	"mistral": {
		"logit_bias": true,
		"n":          true,
	},
	"xai": {
		"logit_bias": true,
		"n":          true,
	},
	"fireworks": {
		"logit_bias": true,
		"n":          true,
	},
	"perplexity": {
		"logit_bias":        true,
		"n":                 true,
		"presence_penalty":  true,
		"frequency_penalty": true,
	},
	"databricks": {
		"logit_bias": true,
		"n":          true,
	},
}

// ParamFilter handles per-provider parameter compatibility by stripping
// unsupported fields from ChatCompletionRequest before forwarding.
type ParamFilter struct{}

// NewParamFilter creates a new ParamFilter.
func NewParamFilter() *ParamFilter {
	return &ParamFilter{}
}

// FilterParams removes parameters from req that the target provider does not
// support. The request is modified in place. If providerType is empty or
// unknown, no filtering is performed (pass-through).
func (f *ParamFilter) FilterParams(providerType string, req *ChatCompletionRequest) {
	if req == nil {
		return
	}
	unsupported, ok := paramSupport[providerType]
	if !ok {
		return
	}
	if unsupported["logit_bias"] {
		req.LogitBias = nil
	}
	if unsupported["n"] {
		req.N = nil
	}
	if unsupported["presence_penalty"] {
		req.PresencePenalty = nil
	}
	if unsupported["frequency_penalty"] {
		req.FrequencyPenalty = nil
	}
	if unsupported["seed"] {
		req.Seed = nil
	}
}

// UnsupportedParams returns the list of parameter names that the given provider
// does not support. Returns nil for unknown providers or providers that support
// all parameters.
func (f *ParamFilter) UnsupportedParams(providerType string) []string {
	unsupported, ok := paramSupport[providerType]
	if !ok || len(unsupported) == 0 {
		return nil
	}
	result := make([]string, 0, len(unsupported))
	for param := range unsupported {
		result = append(result, param)
	}
	return result
}
