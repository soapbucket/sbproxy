// Package providers contains AI provider implementations for routing requests to upstream LLM services.
package providers

import (
	"bytes"
	"context"
	json "github.com/goccy/go-json"
	"fmt"
	"io"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func init() {
	ai.RegisterProvider("azure", NewAzure)
}

// Azure implements the Provider interface for Azure OpenAI Service.
type Azure struct {
	client *http.Client
}

// NewAzure creates and initializes a new Azure.
func NewAzure(client *http.Client) ai.Provider {
	return &Azure{client: client}
}

// Name performs the name operation on the Azure.
func (a *Azure) Name() string            { return "azure" }
// SupportsStreaming performs the supports streaming operation on the Azure.
func (a *Azure) SupportsStreaming() bool  { return true }
// SupportsEmbeddings performs the supports embeddings operation on the Azure.
func (a *Azure) SupportsEmbeddings() bool { return true }

// ChatCompletion performs the chat completion operation on the Azure.
func (a *Azure) ChatCompletion(ctx context.Context, req *ai.ChatCompletionRequest, cfg *ai.ProviderConfig) (*ai.ChatCompletionResponse, error) {
	httpReq, err := a.buildChatRequest(ctx, req, cfg, false)
	if err != nil {
		return nil, err
	}

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("azure: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, extractAzureError(resp)
	}

	var result ai.ChatCompletionResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("azure: decode response: %w", err)
	}
	return &result, nil
}

// ChatCompletionStream performs the chat completion stream operation on the Azure.
func (a *Azure) ChatCompletionStream(ctx context.Context, req *ai.ChatCompletionRequest, cfg *ai.ProviderConfig) (ai.StreamReader, error) {
	httpReq, err := a.buildChatRequest(ctx, req, cfg, true)
	if err != nil {
		return nil, err
	}

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("azure: stream request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, extractAzureError(resp)
	}

	// Azure uses OpenAI-compatible streaming format
	return &openAIStreamReader{
		parser: ai.NewSSEParser(resp.Body, 0),
		body:   resp.Body,
	}, nil
}

// Embeddings performs the embeddings operation on the Azure.
func (a *Azure) Embeddings(ctx context.Context, req *ai.EmbeddingRequest, cfg *ai.ProviderConfig) (*ai.EmbeddingResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("azure: marshal embedding request: %w", err)
	}

	deployment := a.resolveDeployment(req.Model, cfg)
	url := fmt.Sprintf("%s/openai/deployments/%s/embeddings?api-version=%s",
		cfg.BaseURL, deployment, cfg.APIVersion)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	setAzureHeaders(httpReq, cfg)

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("azure: embedding request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, extractAzureError(resp)
	}

	var result ai.EmbeddingResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("azure: decode embedding response: %w", err)
	}
	return &result, nil
}

// ListModels performs the list models operation on the Azure.
func (a *Azure) ListModels(_ context.Context, _ *ai.ProviderConfig) ([]ai.ModelInfo, error) {
	// Azure doesn't have a general models endpoint; models are deployments
	return nil, nil
}

func (a *Azure) buildChatRequest(ctx context.Context, req *ai.ChatCompletionRequest, cfg *ai.ProviderConfig, stream bool) (*http.Request, error) {
	providerReq := *req
	providerReq.SBTags = nil
	providerReq.SBCacheControl = nil
	providerReq.SBPriority = nil

	if stream {
		t := true
		providerReq.Stream = &t
		if providerReq.StreamOptions == nil {
			providerReq.StreamOptions = &ai.StreamOptions{IncludeUsage: true}
		}
	} else {
		providerReq.Stream = nil
		providerReq.StreamOptions = nil
	}

	// Azure uses deployment name, not model name in URL
	deployment := a.resolveDeployment(req.Model, cfg)
	// Clear model from body for Azure (it uses the deployment in the URL)
	providerReq.Model = ""

	body, err := json.Marshal(providerReq)
	if err != nil {
		return nil, fmt.Errorf("azure: marshal request: %w", err)
	}

	apiVersion := cfg.APIVersion
	if apiVersion == "" {
		apiVersion = "2024-02-01"
	}

	url := fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=%s",
		cfg.BaseURL, deployment, apiVersion)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	setAzureHeaders(httpReq, cfg)

	return httpReq, nil
}

func (a *Azure) resolveDeployment(model string, cfg *ai.ProviderConfig) string {
	if cfg.DeploymentMap != nil {
		if deployment, ok := cfg.DeploymentMap[model]; ok {
			return deployment
		}
	}
	// Fall back to model name as deployment name
	return model
}

func setAzureHeaders(req *http.Request, cfg *ai.ProviderConfig) {
	req.Header.Set("Content-Type", "application/json")
	if cfg.APIKey != "" {
		req.Header.Set("api-key", cfg.APIKey)
	}
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}
}

func extractAzureError(resp *http.Response) *ai.AIError {
	body, _ := io.ReadAll(resp.Body)

	// Azure returns OpenAI-compatible errors
	var errResp ai.ErrorResponse
	if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error.Message != "" {
		errResp.Error.StatusCode = resp.StatusCode
		return &errResp.Error
	}

	return &ai.AIError{
		StatusCode: resp.StatusCode,
		Type:       "api_error",
		Message:    fmt.Sprintf("Azure OpenAI API error: %s", string(body)),
	}
}
