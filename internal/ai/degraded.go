// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"context"
	"fmt"
	json "github.com/goccy/go-json"
	"log/slog"
	"time"
)

// DegradedConfig controls fallback behavior when all providers are unavailable.
type DegradedConfig struct {
	// Mode controls the degradation strategy:
	// "stale_cache" - serve expired cache entries with a degraded header
	// "static_response" - return a preconfigured static response
	// "error" - return a structured 503 error (default)
	Mode string `json:"mode,omitempty"`
	// StaticResponse is the fallback message returned when Mode is "static_response".
	StaticResponse string `json:"static_response,omitempty"`
}

// tryDegradedResponse attempts to produce a fallback response after all providers have failed.
// It returns the response and true if a degraded response was produced, or nil and false otherwise.
func (h *Handler) tryDegradedResponse(ctx context.Context, req *ChatCompletionRequest, semanticPromptText string) (*ChatCompletionResponse, bool) {
	cfg := h.config.Degraded
	if cfg == nil {
		return nil, false
	}

	mode := cfg.Mode
	if mode == "" {
		mode = "error"
	}

	switch mode {
	case "stale_cache":
		return h.tryStaleCache(ctx, req, semanticPromptText)
	case "static_response":
		if cfg.StaticResponse == "" {
			return nil, false
		}
		resp := buildStaticResponse(req.Model, cfg.StaticResponse)
		AIDegradedResponse("static_response")
		slog.Warn("serving static degraded response",
			"model", req.Model,
			"reason", "all_providers_failed",
		)
		return resp, true
	default:
		// "error" mode - let the caller handle the error response
		return nil, false
	}
}

// tryStaleCache attempts to serve a stale (expired) cache entry as a degraded response.
func (h *Handler) tryStaleCache(ctx context.Context, req *ChatCompletionRequest, semanticPromptText string) (*ChatCompletionResponse, bool) {
	if h.config.Cache == nil {
		return nil, false
	}

	// Build prompt text if not already available
	promptText := semanticPromptText
	if promptText == "" {
		promptText = h.semanticCachePromptText(req.Messages)
	}
	if promptText == "" {
		return nil, false
	}

	cached, hit, _ := h.config.Cache.LookupStale(ctx, promptText, req.Model)
	if !hit || len(cached) == 0 {
		return nil, false
	}

	var resp ChatCompletionResponse
	if err := json.Unmarshal(cached, &resp); err != nil {
		slog.Warn("failed to unmarshal stale cache for degraded response", "error", err)
		return nil, false
	}

	AIDegradedResponse("stale_cache")
	slog.Warn("serving stale cache as degraded response",
		"model", req.Model,
		"reason", "all_providers_failed",
	)
	return &resp, true
}

// buildStaticResponse creates a ChatCompletionResponse with the given static text.
func buildStaticResponse(model, text string) *ChatCompletionResponse {
	contentJSON, _ := json.Marshal(text)
	finishReason := "stop"
	return &ChatCompletionResponse{
		ID:      fmt.Sprintf("chatcmpl-degraded-%d", time.Now().UnixNano()),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   model,
		Choices: []Choice{{
			Index: 0,
			Message: Message{
				Role:    "assistant",
				Content: contentJSON,
			},
			FinishReason: &finishReason,
		}},
	}
}
