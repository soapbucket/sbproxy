// Package routing provides context window validation, fallback, and parameter management for AI routing.
package routing

import (
	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai"
)

// ContextWindowValidator checks if a request fits within a model's context window.
type ContextWindowValidator struct {
	registry     *ai.ProviderRegistry
	safetyMargin float64 // 0.0 to 1.0, default 0.05 (5%)
}

// NewContextWindowValidator creates a validator with the given safety margin.
// Safety margin is clamped to [0.0, 0.5]; out-of-range values default to 0.05.
func NewContextWindowValidator(registry *ai.ProviderRegistry, safetyMargin float64) *ContextWindowValidator {
	if safetyMargin < 0 || safetyMargin > 0.5 {
		safetyMargin = 0.05
	}
	return &ContextWindowValidator{
		registry:     registry,
		safetyMargin: safetyMargin,
	}
}

// Validate checks if the request fits within the model's context window.
// Returns nil if validation passes or should be skipped (unknown model).
func (v *ContextWindowValidator) Validate(req *ai.ChatCompletionRequest, model string) error {
	if v.registry == nil {
		return nil
	}

	modelDef, _, ok := v.registry.GetModel(model)
	if !ok || modelDef.ContextWindow == 0 {
		return nil // Unknown model or no context window info: skip validation
	}

	estimated := v.estimateInputTokens(req)
	maxOutput := 4096 // Default output reservation
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		maxOutput = *req.MaxTokens
	} else if req.MaxCompletionTokens != nil && *req.MaxCompletionTokens > 0 {
		maxOutput = *req.MaxCompletionTokens
	}

	effectiveWindow := int(float64(modelDef.ContextWindow) * (1.0 - v.safetyMargin))

	if estimated+maxOutput > effectiveWindow {
		return &ai.ContextWindowError{
			Model:           model,
			ContextWindow:   modelDef.ContextWindow,
			EstimatedInput:  estimated,
			RequestedOutput: maxOutput,
		}
	}
	return nil
}

// estimateInputTokens provides a rough token count for the request.
// Uses a ~4 chars per token heuristic when tiktoken is not available.
func (v *ContextWindowValidator) estimateInputTokens(req *ai.ChatCompletionRequest) int {
	total := 0

	for _, msg := range req.Messages {
		// Role overhead (~1 token)
		total += 1

		// Content tokens - Content is json.RawMessage, so we need to parse it
		total += v.estimateContentTokens(msg.Content)

		// Tool call tokens
		for _, tc := range msg.ToolCalls {
			total += len(tc.Function.Name) / 4
			total += len(tc.Function.Arguments) / 4
			total += 3 // framing overhead per tool call
		}
	}

	// Tool definitions
	for _, tool := range req.Tools {
		total += 20 // Base overhead per tool definition
		if tool.Function.Description != "" {
			total += len(tool.Function.Description) / 4
		}
		if len(tool.Function.Parameters) > 0 {
			total += len(tool.Function.Parameters) / 4
		}
	}

	// Message framing tokens
	total += 4

	return total
}

// estimateContentTokens estimates tokens from a message's Content field.
// Content can be a JSON string or an array of content parts.
func (v *ContextWindowValidator) estimateContentTokens(content json.RawMessage) int {
	if len(content) == 0 {
		return 0
	}

	switch content[0] {
	case '"':
		// Simple string content
		var s string
		if err := json.Unmarshal(content, &s); err == nil {
			return len(s) / 4
		}
	case '[':
		// Array of content parts
		var parts []ai.ContentPart
		if err := json.Unmarshal(content, &parts); err == nil {
			total := 0
			for _, part := range parts {
				switch part.Type {
				case "text":
					total += len(part.Text) / 4
				case "image_url":
					total += 85 // Base image token cost (rough estimate)
				}
			}
			return total
		}
	}

	// Fallback: treat the raw bytes as text
	return len(content) / 4
}
