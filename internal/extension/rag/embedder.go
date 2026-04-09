package rag

import (
	"context"
	"fmt"

	"github.com/soapbucket/sbproxy/internal/request/classifier"
)

// Embedder generates vector embeddings from text using an external API.
type Embedder struct {
	client     *HTTPClient
	model      string
	dimensions int
	provider   string // "openai", "cohere", or custom
}

// NewEmbedder creates an Embedder for the given provider.
// Supported providers: "openai" (default), "cohere", or a custom provider
// where apiKey is treated as a bearer token and model/dimensions are passed through.
func NewEmbedder(provider, apiKey, model string, dimensions int) *Embedder {
	var baseURL string
	switch provider {
	case "cohere":
		baseURL = "https://api.cohere.com"
	default:
		// OpenAI and custom providers use OpenAI-compatible format.
		baseURL = "https://api.openai.com"
	}

	client := NewHTTPClient(baseURL, WithBearerAuth(apiKey))

	return &Embedder{
		client:     client,
		model:      model,
		dimensions: dimensions,
		provider:   provider,
	}
}

// NewEmbedderWithBaseURL creates an Embedder with a custom base URL.
// Useful for self-hosted or alternative embedding services.
func NewEmbedderWithBaseURL(baseURL, apiKey, model string, dimensions int) *Embedder {
	client := NewHTTPClient(baseURL, WithBearerAuth(apiKey))
	return &Embedder{
		client:     client,
		model:      model,
		dimensions: dimensions,
		provider:   "custom",
	}
}

// openaiEmbedRequest is the request body for OpenAI-compatible /v1/embeddings.
type openaiEmbedRequest struct {
	Model      string `json:"model"`
	Input      any    `json:"input"` // string or []string
	Dimensions int    `json:"dimensions,omitempty"`
}

// openaiEmbedResponse is the response from OpenAI-compatible /v1/embeddings.
type openaiEmbedResponse struct {
	Data []struct {
		Embedding []float32 `json:"embedding"`
	} `json:"data"`
}

// cohereEmbedRequest is the request body for Cohere /v2/embed.
type cohereEmbedRequest struct {
	Model          string   `json:"model"`
	Texts          []string `json:"texts"`
	InputType      string   `json:"input_type"`
	EmbeddingTypes []string `json:"embedding_types"`
}

// cohereEmbedResponse is the response from Cohere /v2/embed.
type cohereEmbedResponse struct {
	Embeddings struct {
		Float [][]float32 `json:"float"`
	} `json:"embeddings"`
}

// Embed generates an embedding vector for a single text string.
func (e *Embedder) Embed(ctx context.Context, text string) ([]float32, error) {
	if e.provider == "local" {
		return e.embedLocal(ctx, text)
	}
	if e.provider == "cohere" {
		return e.embedCohere(ctx, []string{text}, true)
	}
	return e.embedOpenAI(ctx, text)
}

// EmbedBatch generates embedding vectors for multiple text strings.
func (e *Embedder) EmbedBatch(ctx context.Context, texts []string) ([][]float32, error) {
	if len(texts) == 0 {
		return nil, nil
	}
	if e.provider == "local" {
		return e.embedBatchLocal(ctx, texts)
	}
	if e.provider == "cohere" {
		return e.embedBatchCohere(ctx, texts)
	}
	return e.embedBatchOpenAI(ctx, texts)
}

// embedOpenAI calls the OpenAI-compatible /v1/embeddings endpoint for a single text.
func (e *Embedder) embedOpenAI(ctx context.Context, text string) ([]float32, error) {
	req := openaiEmbedRequest{
		Model:      e.model,
		Input:      text,
		Dimensions: e.dimensions,
	}

	var resp openaiEmbedResponse
	if err := e.client.Do(ctx, "POST", "/v1/embeddings", req, &resp); err != nil {
		return nil, fmt.Errorf("openai embed: %w", err)
	}

	if len(resp.Data) == 0 {
		return nil, fmt.Errorf("openai embed: empty response")
	}

	return resp.Data[0].Embedding, nil
}

// embedBatchOpenAI calls /v1/embeddings with multiple inputs.
func (e *Embedder) embedBatchOpenAI(ctx context.Context, texts []string) ([][]float32, error) {
	req := openaiEmbedRequest{
		Model:      e.model,
		Input:      texts,
		Dimensions: e.dimensions,
	}

	var resp openaiEmbedResponse
	if err := e.client.Do(ctx, "POST", "/v1/embeddings", req, &resp); err != nil {
		return nil, fmt.Errorf("openai embed batch: %w", err)
	}

	if len(resp.Data) != len(texts) {
		return nil, fmt.Errorf("openai embed batch: expected %d embeddings, got %d", len(texts), len(resp.Data))
	}

	result := make([][]float32, len(resp.Data))
	for i, d := range resp.Data {
		result[i] = d.Embedding
	}
	return result, nil
}

// embedCohere calls Cohere /v2/embed for a single text. Returns the first embedding.
func (e *Embedder) embedCohere(ctx context.Context, texts []string, _ bool) ([]float32, error) {
	req := cohereEmbedRequest{
		Model:          e.model,
		Texts:          texts,
		InputType:      "search_query",
		EmbeddingTypes: []string{"float"},
	}

	var resp cohereEmbedResponse
	if err := e.client.Do(ctx, "POST", "/v2/embed", req, &resp); err != nil {
		return nil, fmt.Errorf("cohere embed: %w", err)
	}

	if len(resp.Embeddings.Float) == 0 {
		return nil, fmt.Errorf("cohere embed: empty response")
	}

	return resp.Embeddings.Float[0], nil
}

// embedBatchCohere calls Cohere /v2/embed for multiple texts.
func (e *Embedder) embedBatchCohere(ctx context.Context, texts []string) ([][]float32, error) {
	req := cohereEmbedRequest{
		Model:          e.model,
		Texts:          texts,
		InputType:      "search_document",
		EmbeddingTypes: []string{"float"},
	}

	var resp cohereEmbedResponse
	if err := e.client.Do(ctx, "POST", "/v2/embed", req, &resp); err != nil {
		return nil, fmt.Errorf("cohere embed batch: %w", err)
	}

	if len(resp.Embeddings.Float) != len(texts) {
		return nil, fmt.Errorf("cohere embed batch: expected %d embeddings, got %d", len(texts), len(resp.Embeddings.Float))
	}

	return resp.Embeddings.Float, nil
}

// embedLocal generates an embedding using the classifier sidecar.
func (e *Embedder) embedLocal(_ context.Context, text string) ([]float32, error) {
	mc := classifier.Global()
	if mc == nil || !mc.IsEmbedSupported() {
		return nil, fmt.Errorf("local embedding: classifier sidecar not available")
	}
	return mc.EmbedOne(text)
}

// embedBatchLocal generates embeddings for multiple texts using the classifier sidecar.
func (e *Embedder) embedBatchLocal(_ context.Context, texts []string) ([][]float32, error) {
	mc := classifier.Global()
	if mc == nil || !mc.IsEmbedSupported() {
		return nil, fmt.Errorf("local embedding: classifier sidecar not available")
	}
	resp, err := mc.Embed(texts...)
	if err != nil {
		return nil, err
	}
	return resp.Embeddings, nil
}
