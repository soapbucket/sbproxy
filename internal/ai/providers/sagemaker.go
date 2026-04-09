// Package providers contains AI provider implementations for routing requests to upstream LLM services.
//
// The SageMaker provider requires the enterprise build with AWS SDK. In the core build,
// the provider registers but returns an error when used.
package providers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func init() {
	ai.RegisterProvider("sagemaker", NewSageMaker)
}

// SageMaker implements the Provider interface for AWS SageMaker endpoints.
// In the core build this is a stub that returns errors for all operations.
type SageMaker struct {
	client *http.Client
}

// NewSageMaker creates and initializes a new SageMaker provider.
func NewSageMaker(client *http.Client) ai.Provider {
	return &SageMaker{client: client}
}

// Name returns the provider name.
func (s *SageMaker) Name() string { return "sagemaker" }

// SupportsStreaming returns true because SageMaker supports SSE streaming.
func (s *SageMaker) SupportsStreaming() bool { return true }

// SupportsEmbeddings returns true because SageMaker can host embedding models.
func (s *SageMaker) SupportsEmbeddings() bool { return true }

// errSageMakerNotAvailable is returned for all operations in the core build.
var errSageMakerNotAvailable = fmt.Errorf("sagemaker: provider not available in core build (requires enterprise AWS dependency)")

// ChatCompletion is not available in the core build.
func (s *SageMaker) ChatCompletion(_ context.Context, _ *ai.ChatCompletionRequest, _ *ai.ProviderConfig) (*ai.ChatCompletionResponse, error) {
	return nil, errSageMakerNotAvailable
}

// ChatCompletionStream is not available in the core build.
func (s *SageMaker) ChatCompletionStream(_ context.Context, _ *ai.ChatCompletionRequest, _ *ai.ProviderConfig) (ai.StreamReader, error) {
	return nil, errSageMakerNotAvailable
}

// Embeddings is not available in the core build.
func (s *SageMaker) Embeddings(_ context.Context, _ *ai.EmbeddingRequest, _ *ai.ProviderConfig) (*ai.EmbeddingResponse, error) {
	return nil, errSageMakerNotAvailable
}

// ListModels returns nil because SageMaker endpoints do not have a standard model listing API.
func (s *SageMaker) ListModels(_ context.Context, _ *ai.ProviderConfig) ([]ai.ModelInfo, error) {
	return nil, nil
}
