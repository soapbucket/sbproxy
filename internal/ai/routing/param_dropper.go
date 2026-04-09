package routing

import (
	"log/slog"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai"
)

// ParamDropper removes unsupported parameters from a ChatCompletionRequest
// based on the target provider and model capabilities defined in the registry.
// Unlike ParamFilter (which handles provider-level parameter compatibility),
// ParamDropper uses model-level capability information such as vision support,
// tool calling, structured output, and reasoning to clean requests before dispatch.
type ParamDropper struct {
	enabled bool
}

// NewParamDropper creates a ParamDropper. When enabled is false, Clean is a no-op.
func NewParamDropper(enabled bool) *ParamDropper {
	return &ParamDropper{enabled: enabled}
}

// Clean removes unsupported parameters from the request based on provider and model
// capabilities. Returns the list of dropped parameter names (for logging/headers).
// If the dropper is disabled or the model is not found in the registry, no parameters
// are dropped.
func (d *ParamDropper) Clean(req *ai.ChatCompletionRequest, provider *ai.ProviderConfig, registry *ai.ProviderRegistry) ([]string, error) {
	if !d.enabled || req == nil || registry == nil {
		return nil, nil
	}

	modelDef, providerSlug, found := registry.GetModel(req.Model)
	if !found {
		// Model not in registry; cannot determine capabilities, skip dropping.
		return nil, nil
	}
	if provider == nil {
		return nil, nil
	}

	providerName := provider.Name
	if providerName == "" {
		providerName = providerSlug
	}

	var dropped []string

	// Vision: strip image content parts from messages if the model does not support vision.
	if !modelDef.SupportsVision && hasImageContent(req.Messages) {
		stripImageContent(req)
		dropped = append(dropped, "vision_content")
		slog.Warn("param_dropper: stripped image content from messages",
			"provider", providerName, "model", req.Model, "param", "vision_content")
	}

	// Tools / function calling: drop if the model explicitly does not support tools.
	if modelDef.SupportsTools != nil && !*modelDef.SupportsTools {
		if len(req.Tools) > 0 || len(req.ToolChoice) > 0 {
			req.Tools = nil
			req.ToolChoice = nil
			dropped = append(dropped, "tools")
			slog.Warn("param_dropper: dropped tools and tool_choice",
				"provider", providerName, "model", req.Model, "param", "tools")
		}
	}

	// ResponseFormat / structured output: drop if provider is known not to support it.
	// Models that don't support structured output are detected by provider type heuristic
	// since there is no explicit field in ModelDef for this.
	if req.ResponseFormat != nil && !supportsStructuredOutput(provider.GetType()) {
		dropped = append(dropped, "response_format")
		slog.Warn("param_dropper: dropped response_format",
			"provider", providerName, "model", req.Model, "param", "response_format")
		req.ResponseFormat = nil
	}

	// Thinking / ReasoningEffort: drop if the model is not a reasoning model.
	if !modelDef.IsReasoning {
		if req.Thinking != nil {
			req.Thinking = nil
			dropped = append(dropped, "thinking")
			slog.Warn("param_dropper: dropped thinking config",
				"provider", providerName, "model", req.Model, "param", "thinking")
		}
		if req.ReasoningEffort != "" {
			req.ReasoningEffort = ""
			dropped = append(dropped, "reasoning_effort")
			slog.Warn("param_dropper: dropped reasoning_effort",
				"provider", providerName, "model", req.Model, "param", "reasoning_effort")
		}
	}

	// Streaming: warn but do not drop. Dropping streaming mid-request would break
	// the caller's expectations for the response format.
	if req.IsStreaming() && modelDef.SupportsStreaming != nil && !*modelDef.SupportsStreaming {
		slog.Warn("param_dropper: model does not support streaming but stream=true was requested; not dropping",
			"provider", providerName, "model", req.Model, "param", "stream")
	}

	return dropped, nil
}

// hasImageContent returns true if any message contains an image_url content part.
func hasImageContent(msgs []ai.Message) bool {
	for i := range msgs {
		if len(msgs[i].Content) == 0 || msgs[i].Content[0] != '[' {
			continue
		}
		var parts []ai.ContentPart
		if err := json.Unmarshal(msgs[i].Content, &parts); err != nil {
			continue
		}
		for _, p := range parts {
			if p.Type == "image_url" && p.ImageURL != nil {
				return true
			}
		}
	}
	return false
}

// stripImageContent removes image_url content parts from all messages,
// keeping only text parts. If a message ends up with no content parts,
// it is replaced with an empty string content.
func stripImageContent(req *ai.ChatCompletionRequest) {
	for i := range req.Messages {
		if len(req.Messages[i].Content) == 0 || req.Messages[i].Content[0] != '[' {
			continue
		}
		var parts []ai.ContentPart
		if err := json.Unmarshal(req.Messages[i].Content, &parts); err != nil {
			continue
		}
		var hasImage bool
		var textParts []ai.ContentPart
		for _, p := range parts {
			if p.Type == "image_url" {
				hasImage = true
				continue
			}
			textParts = append(textParts, p)
		}
		if !hasImage {
			continue
		}
		if len(textParts) == 0 {
			// No text parts remain; set content to empty string.
			req.Messages[i].Content = json.RawMessage(`""`)
		} else if len(textParts) == 1 && textParts[0].Type == "text" {
			// Single text part: simplify to a plain string.
			raw, err := json.Marshal(textParts[0].Text)
			if err == nil {
				req.Messages[i].Content = raw
			}
		} else {
			raw, err := json.Marshal(textParts)
			if err == nil {
				req.Messages[i].Content = raw
			}
		}
	}
}

// supportsStructuredOutput returns true if the provider type is known to support
// the response_format parameter with JSON schema.
func supportsStructuredOutput(providerType string) bool {
	switch providerType {
	case "openai", "azure", "generic", "fireworks", "xai", "databricks":
		return true
	default:
		// Providers like ollama, perplexity, cohere, jina, etc. may not support it.
		return false
	}
}
