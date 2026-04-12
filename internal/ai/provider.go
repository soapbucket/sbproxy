// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/soapbucket/sbproxy/internal/ai/limits"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// Operation is a string type that represents operation.
type Operation string

const (
	// OperationChatCompletions is a constant for operation chat completions.
	OperationChatCompletions Operation = "chat_completions"
	// OperationResponses is a constant for operation responses.
	OperationResponses Operation = "responses"
	// OperationEmbeddings is a constant for operation embeddings.
	OperationEmbeddings Operation = "embeddings"
	// OperationModels is a constant for operation reqctx.
	OperationModels Operation = "models"
	// OperationModerations is a constant for operation moderations.
	OperationModerations Operation = "moderations"
	// OperationBatches is a constant for operation batches.
	OperationBatches Operation = "batches"
	// OperationFiles is a constant for operation files.
	OperationFiles Operation = "files"
	// OperationImagesGenerations is a constant for operation images generations.
	OperationImagesGenerations Operation = "images_generations"
	// OperationAudioSpeech is a constant for operation audio speech.
	OperationAudioSpeech Operation = "audio_speech"
	// OperationAudioTranscribe is a constant for operation audio transcribe.
	OperationAudioTranscribe Operation = "audio_transcriptions"
	// OperationRerank is a constant for reranking operations.
	OperationRerank Operation = "rerank"
)

// Provider translates between OpenAI-format requests and a specific LLM API.
type Provider interface {
	// Name returns the provider identifier (e.g., "openai", "anthropic").
	Name() string

	// ChatCompletion sends a non-streaming chat request and returns the response.
	ChatCompletion(ctx context.Context, req *ChatCompletionRequest, cfg *ProviderConfig) (*ChatCompletionResponse, error)

	// ChatCompletionStream sends a streaming chat request and returns a StreamReader.
	// The caller MUST call StreamReader.Close() when done.
	ChatCompletionStream(ctx context.Context, req *ChatCompletionRequest, cfg *ProviderConfig) (StreamReader, error)

	// Embeddings generates embeddings for the given input.
	Embeddings(ctx context.Context, req *EmbeddingRequest, cfg *ProviderConfig) (*EmbeddingResponse, error)

	// ListModels returns the models available on this provider.
	ListModels(ctx context.Context, cfg *ProviderConfig) ([]ModelInfo, error)

	// SupportsStreaming returns true if the provider supports SSE streaming.
	SupportsStreaming() bool

	// SupportsEmbeddings returns true if the provider supports embeddings.
	SupportsEmbeddings() bool
}

// StreamReader reads normalized StreamChunks from a provider's streaming response.
type StreamReader interface {
	// Read returns the next chunk. Returns io.EOF when the stream ends.
	Read() (*StreamChunk, error)

	// Close releases resources. Must be called.
	Close() error
}

// ProviderConfig holds per-provider connection settings loaded from JSON config.
type ProviderConfig struct {
	Name          string            `json:"name"`
	Type          string            `json:"type,omitempty"`
	APIKey        string            `json:"api_key,omitempty" secret:"true"`
	BaseURL       string            `json:"base_url,omitempty"`
	Models        []string          `json:"models,omitempty"`
	DefaultModel  string            `json:"default_model,omitempty"`
	ModelMap      map[string]string `json:"model_map,omitempty"`
	Weight        int               `json:"weight,omitempty"`
	Priority      int               `json:"priority,omitempty"`
	MaxRetries    int               `json:"max_retries,omitempty"`
	Timeout       reqctx.Duration   `json:"timeout,omitempty" validate:"max_value=5m,default_value=30s"`
	Headers       map[string]string `json:"headers,omitempty"`
	Organization  string            `json:"organization,omitempty"`
	ProjectID     string            `json:"project_id,omitempty"`
	Region        string            `json:"region,omitempty"`
	APIVersion    string            `json:"api_version,omitempty"`
	DeploymentMap map[string]string `json:"deployment_map,omitempty"`
	Format        string            `json:"format,omitempty"`      // "openai" (default), "anthropic", "passthrough"
	AuthHeader    string            `json:"auth_header,omitempty"` // Custom auth header name (e.g., "X-Api-Key")
	AuthPrefix    string            `json:"auth_prefix,omitempty"` // Custom auth prefix (e.g., "Token")
	Enabled       *bool             `json:"enabled,omitempty"`

	MaxTokensPerMin   int `json:"max_tokens_per_minute,omitempty"`
	MaxRequestsPerMin int `json:"max_requests_per_minute,omitempty"`

	// RateLimits configures per-model rate limits for this provider.
	// Keys are model names, values define RPM and TPM limits.
	RateLimits map[string]limits.ModelRateConfig `json:"rate_limits,omitempty"`

	// HealthCheck configures proactive health checking for this provider.
	HealthCheck *HealthCheckConfig `json:"health_check,omitempty"`
}

// IsEnabled returns true if the provider is enabled (defaults to true).
func (pc *ProviderConfig) IsEnabled() bool {
	return pc.Enabled == nil || *pc.Enabled
}

// GetType returns the provider type, defaulting to the name.
func (pc *ProviderConfig) GetType() string {
	if pc.Type != "" {
		return pc.Type
	}
	return pc.Name
}

// ResolveModel maps an incoming model name to the provider's model name.
func (pc *ProviderConfig) ResolveModel(model string) string {
	if pc.ModelMap != nil {
		if mapped, ok := pc.ModelMap[model]; ok {
			return mapped
		}
	}
	return model
}

// SupportsModel returns true if this provider serves the given model.
func (pc *ProviderConfig) SupportsModel(model string) bool {
	if len(pc.Models) == 0 {
		return true // no restriction
	}
	for _, m := range pc.Models {
		if m == model {
			return true
		}
	}
	// Check model map
	if pc.ModelMap != nil {
		if _, ok := pc.ModelMap[model]; ok {
			return true
		}
	}
	return false
}

// SupportsOperation reports whether this provider type can serve a given endpoint family.
// It is intentionally conservative for non-chat endpoint families so routing does not
// select providers that are known to lack a compatible surface.
func (pc *ProviderConfig) SupportsOperation(op Operation) bool {
	switch pc.GetType() {
	case "openai", "generic", "sagemaker", "oracle",
		"xai", "fireworks", "perplexity", "databricks":
		return true
	case "azure":
		switch op {
		case OperationChatCompletions,
			OperationResponses,
			OperationEmbeddings,
			OperationModerations,
			OperationBatches,
			OperationFiles,
			OperationImagesGenerations,
			OperationAudioSpeech,
			OperationAudioTranscribe:
			return true
		default:
			return op == OperationModels
		}
	case "anthropic", "bedrock":
		switch op {
		case OperationChatCompletions, OperationEmbeddings, OperationModels:
			return true
		default:
			return false
		}
	case "watsonx":
		switch op {
		case OperationChatCompletions, OperationEmbeddings, OperationModels:
			return true
		default:
			return false
		}
	case "gemini":
		switch op {
		case OperationChatCompletions, OperationEmbeddings, OperationModels:
			return true
		default:
			return false
		}
	case "cohere":
		switch op {
		case OperationChatCompletions, OperationEmbeddings, OperationModels, OperationRerank:
			return true
		default:
			return false
		}
	case "jina":
		switch op {
		case OperationEmbeddings, OperationRerank:
			return true
		default:
			return false
		}
	default:
		return op == OperationChatCompletions || op == OperationEmbeddings || op == OperationModels
	}
}

// ProviderConstructorFn creates a Provider from config and an HTTP client.
type ProviderConstructorFn func(httpClient *http.Client) Provider

var (
	providerRegistry   = map[string]ProviderConstructorFn{}
	providerRegistryMu sync.RWMutex
)

// RegisterProvider registers a provider constructor.
func RegisterProvider(name string, fn ProviderConstructorFn) {
	providerRegistryMu.Lock()
	defer providerRegistryMu.Unlock()
	providerRegistry[name] = fn
}

// NewProvider creates a provider from config.
func NewProvider(cfg *ProviderConfig, httpClient *http.Client) (Provider, error) {
	providerRegistryMu.RLock()
	defer providerRegistryMu.RUnlock()

	providerType := cfg.GetType()
	fn, ok := providerRegistry[providerType]
	if !ok {
		// Fallback to generic OpenAI-compatible provider
		fn, ok = providerRegistry["generic"]
	}
	if !ok || fn == nil {
		return nil, fmt.Errorf("unknown provider type: %s", providerType)
	}
	return fn(httpClient), nil
}
