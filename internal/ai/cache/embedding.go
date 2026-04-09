// Package cache implements semantic caching for AI responses using vector similarity search.
package cache

import (
	"context"
	"crypto/sha256"
	"fmt"
)

// EmbedFunc generates an embedding for text. Injected by handler to avoid circular deps.
type EmbedFunc func(ctx context.Context, text string) ([]float32, error)

// Embedder wraps an embedding function with prompt normalization.
type Embedder struct {
	embedFn       EmbedFunc
	maxTokens     int
}

// NewEmbedder creates an embedder with the given embedding function.
func NewEmbedder(fn EmbedFunc, maxTokens int) *Embedder {
	if maxTokens <= 0 {
		maxTokens = 512
	}
	return &Embedder{embedFn: fn, maxTokens: maxTokens}
}

// Embed generates an embedding for the text, truncating to maxTokens.
func (e *Embedder) Embed(ctx context.Context, text string) ([]float32, error) {
	truncated := truncateToTokens(text, e.maxTokens)
	return e.embedFn(ctx, truncated)
}

// CacheKey generates a cache key from the prompt and optional model.
func CacheKey(prompt, model string, crossProvider bool) string {
	return CacheKeyWithNamespace("", prompt, model, crossProvider)
}

// CacheKeyWithNamespace generates a cache key from an optional namespace, prompt, and model.
func CacheKeyWithNamespace(namespace, prompt, model string, crossProvider bool) string {
	h := sha256.New()
	if namespace != "" {
		h.Write([]byte(namespace))
		h.Write([]byte{0})
	}
	if !crossProvider {
		h.Write([]byte(model))
		h.Write([]byte{0})
	}
	h.Write([]byte(prompt))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// truncateToTokens truncates text to approximately the given token count.
// Uses chars/4 estimation.
func truncateToTokens(text string, maxTokens int) string {
	maxChars := maxTokens * 4
	if len(text) <= maxChars {
		return text
	}
	return text[:maxChars]
}

// ExtractPromptText extracts user message text from a message list,
// excluding system prompts for embedding cost efficiency.
func ExtractPromptText(messages []map[string]interface{}) string {
	var text string
	for _, msg := range messages {
		role, _ := msg["role"].(string)
		if role == "system" {
			continue
		}
		content, _ := msg["content"].(string)
		if content != "" {
			if text != "" {
				text += "\n"
			}
			text += content
		}
	}
	return text
}
