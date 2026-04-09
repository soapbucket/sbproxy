// Package providers contains AI provider implementations for routing requests to upstream LLM services.
//
// The Bedrock provider requires the enterprise build with AWS SDK. In the core build,
// the provider registers but returns an error when used.
package providers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func init() {
	ai.RegisterProvider("bedrock", NewBedrock)
}

// Bedrock implements the Provider interface for AWS Bedrock.
// In the core build this is a stub that returns errors for all operations.
type Bedrock struct {
	client *http.Client
}

// NewBedrock creates and initializes a new Bedrock provider.
func NewBedrock(client *http.Client) ai.Provider {
	return &Bedrock{client: client}
}

// Name returns the provider name.
func (b *Bedrock) Name() string { return "bedrock" }

// SupportsStreaming returns true because Bedrock supports streaming.
func (b *Bedrock) SupportsStreaming() bool { return true }

// SupportsEmbeddings returns true because Bedrock supports embedding models.
func (b *Bedrock) SupportsEmbeddings() bool { return true }

// errBedrockNotAvailable is returned for all operations in the core build.
var errBedrockNotAvailable = fmt.Errorf("bedrock: provider not available in core build (requires enterprise AWS dependency)")

// ChatCompletion is not available in the core build.
func (b *Bedrock) ChatCompletion(_ context.Context, _ *ai.ChatCompletionRequest, _ *ai.ProviderConfig) (*ai.ChatCompletionResponse, error) {
	return nil, errBedrockNotAvailable
}

// ChatCompletionStream is not available in the core build.
func (b *Bedrock) ChatCompletionStream(_ context.Context, _ *ai.ChatCompletionRequest, _ *ai.ProviderConfig) (ai.StreamReader, error) {
	return nil, errBedrockNotAvailable
}

// Embeddings is not available in the core build.
func (b *Bedrock) Embeddings(_ context.Context, _ *ai.EmbeddingRequest, _ *ai.ProviderConfig) (*ai.EmbeddingResponse, error) {
	return nil, errBedrockNotAvailable
}

// ListModels returns nil.
func (b *Bedrock) ListModels(_ context.Context, _ *ai.ProviderConfig) ([]ai.ModelInfo, error) {
	return nil, nil
}
