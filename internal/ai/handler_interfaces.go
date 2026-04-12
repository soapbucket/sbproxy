// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"context"

	"github.com/soapbucket/sbproxy/internal/ai/memory"
)

// SemanticCacher abstracts semantic similarity-based response caching.
// The enterprise implementation lives in internal/ai/cache.
type SemanticCacher interface {
	// Lookup searches for a cached response matching the prompt and model.
	Lookup(ctx context.Context, prompt, model string) ([]byte, bool, error)
	// LookupStale searches for a cached response, returning it even if expired.
	LookupStale(ctx context.Context, prompt, model string) ([]byte, bool, error)
	// Store caches a response with its prompt embedding.
	Store(ctx context.Context, prompt, model string, response []byte) error
	// Health returns the health status of the underlying cache store.
	Health(ctx context.Context) CacheHealthStatus
}

// CacheHealthStatus reports the health status of a cache backend.
type CacheHealthStatus struct {
	StoreType string `json:"store_type"`
	Entries   int64  `json:"entries"`
	Capacity  int    `json:"capacity"`
	Healthy   bool   `json:"healthy"`
	Error     string `json:"error,omitempty"`
}

// MemoryWriter abstracts AI conversation memory persistence.
// The enterprise implementation lives in internal/ai/memory.
type MemoryWriter interface {
	// Write serializes an entry and writes it to the storage backend.
	Write(entry *memory.Entry) error
	// Config returns the memory configuration.
	Config() *memory.MemoryConfig
}

// extractPromptText extracts user message text from a message list,
// excluding system prompts for embedding cost efficiency.
// This is inlined from cache.ExtractPromptText to avoid importing the cache package.
func extractPromptText(messages []map[string]interface{}) string {
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
