// Package cache implements semantic caching for AI responses using vector similarity search.
package cache

import (
	"context"
	"fmt"

	"github.com/soapbucket/sbproxy/internal/request/classifier"
)

// ProviderEmbedder abstracts an embedding provider to avoid circular imports with the ai package.
// Callers implement this by wrapping their provider's Embeddings() method.
type ProviderEmbedder interface {
	Embed(ctx context.Context, text, model string) ([]float32, error)
}

// NewProviderEmbedFunc creates an EmbedFunc that calls a ProviderEmbedder.
// The model parameter specifies which embedding model to use (e.g., "text-embedding-3-small").
func NewProviderEmbedFunc(embedder ProviderEmbedder, model string) EmbedFunc {
	if embedder == nil {
		return nil
	}
	if model == "" {
		model = "text-embedding-3-small"
	}

	return func(ctx context.Context, text string) ([]float32, error) {
		embedding, err := embedder.Embed(ctx, text, model)
		if err != nil {
			return nil, fmt.Errorf("cache embedding error: %w", err)
		}
		return embedding, nil
	}
}

// NewLocalEmbedFunc creates an EmbedFunc that calls the prompt-classifier sidecar
// for local embedding generation, avoiding external API calls.
func NewLocalEmbedFunc(mc *classifier.ManagedClient) EmbedFunc {
	if mc == nil || !mc.IsEmbedSupported() {
		return nil
	}
	return func(ctx context.Context, text string) ([]float32, error) {
		vec, err := mc.EmbedOne(text)
		if err != nil {
			return nil, fmt.Errorf("local embedding error: %w", err)
		}
		return vec, nil
	}
}
