// Package providers contains AI provider implementations for routing requests to upstream LLM services.
package providers

import (
	"bytes"
	"context"
	"fmt"
	json "github.com/goccy/go-json"
	"io"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/ai"
)

const (
	openaiDefaultBaseURL = "https://api.openai.com/v1"
)

func init() {
	ai.RegisterProvider("openai", NewOpenAI)
}

// OpenAI implements the Provider interface for OpenAI's API.
type OpenAI struct {
	client *http.Client
}

// NewOpenAI creates a new OpenAI provider.
func NewOpenAI(client *http.Client) ai.Provider {
	return &OpenAI{client: client}
}

// Name performs the name operation on the OpenAI.
func (o *OpenAI) Name() string { return "openai" }

// SupportsStreaming performs the supports streaming operation on the OpenAI.
func (o *OpenAI) SupportsStreaming() bool { return true }

// SupportsEmbeddings performs the supports embeddings operation on the OpenAI.
func (o *OpenAI) SupportsEmbeddings() bool { return true }

// ChatCompletion performs the chat completion operation on the OpenAI.
func (o *OpenAI) ChatCompletion(ctx context.Context, req *ai.ChatCompletionRequest, cfg *ai.ProviderConfig) (*ai.ChatCompletionResponse, error) {
	httpReq, err := o.buildChatRequest(ctx, req, cfg, false)
	if err != nil {
		return nil, err
	}

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("openai: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, extractOpenAIError(resp)
	}

	var result ai.ChatCompletionResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("openai: decode response: %w", err)
	}
	return &result, nil
}

// ChatCompletionStream performs the chat completion stream operation on the OpenAI.
func (o *OpenAI) ChatCompletionStream(ctx context.Context, req *ai.ChatCompletionRequest, cfg *ai.ProviderConfig) (ai.StreamReader, error) {
	httpReq, err := o.buildChatRequest(ctx, req, cfg, true)
	if err != nil {
		return nil, err
	}

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("openai: stream request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, extractOpenAIError(resp)
	}

	return &openAIStreamReader{
		parser: ai.NewSSEParser(resp.Body, 0),
		body:   resp.Body,
	}, nil
}

// Embeddings performs the embeddings operation on the OpenAI.
func (o *OpenAI) Embeddings(ctx context.Context, req *ai.EmbeddingRequest, cfg *ai.ProviderConfig) (*ai.EmbeddingResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("openai: marshal embedding request: %w", err)
	}

	baseURL := openaiDefaultBaseURL
	if cfg.BaseURL != "" {
		baseURL = cfg.BaseURL
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	setOpenAIHeaders(httpReq, cfg)

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("openai: embedding request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, extractOpenAIError(resp)
	}

	var result ai.EmbeddingResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("openai: decode embedding response: %w", err)
	}
	return &result, nil
}

// ListModels performs the list models operation on the OpenAI.
func (o *OpenAI) ListModels(ctx context.Context, cfg *ai.ProviderConfig) ([]ai.ModelInfo, error) {
	baseURL := openaiDefaultBaseURL
	if cfg.BaseURL != "" {
		baseURL = cfg.BaseURL
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/models", nil)
	if err != nil {
		return nil, err
	}
	setOpenAIHeaders(httpReq, cfg)

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("openai: list models failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, extractOpenAIError(resp)
	}

	var result ai.ModelListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("openai: decode models: %w", err)
	}
	return result.Data, nil
}

func (o *OpenAI) buildChatRequest(ctx context.Context, req *ai.ChatCompletionRequest, cfg *ai.ProviderConfig, stream bool) (*http.Request, error) {
	// Create a copy to modify for the provider
	providerReq := *req
	providerReq.Model = cfg.ResolveModel(req.Model)
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

	body, err := json.Marshal(providerReq)
	if err != nil {
		return nil, fmt.Errorf("openai: marshal request: %w", err)
	}

	baseURL := openaiDefaultBaseURL
	if cfg.BaseURL != "" {
		baseURL = cfg.BaseURL
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	setOpenAIHeaders(httpReq, cfg)

	return httpReq, nil
}

func setOpenAIHeaders(req *http.Request, cfg *ai.ProviderConfig) {
	req.Header.Set("Content-Type", "application/json")
	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}
	if cfg.Organization != "" {
		req.Header.Set("OpenAI-Organization", cfg.Organization)
	}
	if cfg.ProjectID != "" {
		req.Header.Set("OpenAI-Project", cfg.ProjectID)
	}
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}
}

func extractOpenAIError(resp *http.Response) *ai.AIError {
	body, _ := io.ReadAll(resp.Body)

	var errResp ai.ErrorResponse
	if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error.Message != "" {
		errResp.Error.StatusCode = resp.StatusCode
		return &errResp.Error
	}

	return &ai.AIError{
		StatusCode: resp.StatusCode,
		Type:       "api_error",
		Message:    fmt.Sprintf("OpenAI API error: %s", string(body)),
	}
}

// openAIStreamReader reads OpenAI-format SSE events as StreamChunks.
type openAIStreamReader struct {
	parser *ai.SSEParser
	body   io.ReadCloser
}

// Read performs the read operation on the openAIStreamReader.
func (r *openAIStreamReader) Read() (*ai.StreamChunk, error) {
	for {
		event, err := r.parser.ReadEvent()
		if err != nil {
			return nil, err
		}

		if ai.IsDone(event.Data) {
			ai.ReleaseSSEEvent(event)
			return nil, io.EOF
		}

		var chunk ai.StreamChunk
		if err := json.Unmarshal([]byte(event.Data), &chunk); err != nil {
			ai.ReleaseSSEEvent(event)
			continue // skip malformed chunks
		}
		ai.ReleaseSSEEvent(event)
		return &chunk, nil
	}
}

// Close releases resources held by the openAIStreamReader.
func (r *openAIStreamReader) Close() error {
	r.parser.Close()
	return r.body.Close()
}
