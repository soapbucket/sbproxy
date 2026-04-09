// Package providers contains AI provider implementations for routing requests to upstream LLM services.
package providers

import (
	"bytes"
	"context"
	"fmt"
	json "github.com/goccy/go-json"
	"io"
	"net/http"
	"strings"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func init() {
	ai.RegisterProvider("generic", NewGeneric)
}

// Generic implements the Provider interface for any API, supporting OpenAI-compatible
// and passthrough modes.
type Generic struct {
	OpenAI
}

// NewGeneric creates and initializes a new Generic provider.
func NewGeneric(client *http.Client) ai.Provider {
	return &Generic{OpenAI: OpenAI{client: client}}
}

// Name returns the provider name.
func (g *Generic) Name() string { return "generic" }

// ChatCompletion handles chat completions with format awareness.
func (g *Generic) ChatCompletion(ctx context.Context, req *ai.ChatCompletionRequest, cfg *ai.ProviderConfig) (*ai.ChatCompletionResponse, error) {
	if cfg.Format == "passthrough" {
		return g.passthroughCompletion(ctx, req, cfg)
	}
	return g.OpenAI.ChatCompletion(ctx, req, cfg)
}

// ChatCompletionStream handles streaming chat completions with format awareness.
func (g *Generic) ChatCompletionStream(ctx context.Context, req *ai.ChatCompletionRequest, cfg *ai.ProviderConfig) (ai.StreamReader, error) {
	if cfg.Format == "passthrough" {
		return g.passthroughStream(ctx, req, cfg)
	}
	return g.OpenAI.ChatCompletionStream(ctx, req, cfg)
}

// passthroughCompletion forwards the request body as-is and extracts token counts from the response.
func (g *Generic) passthroughCompletion(ctx context.Context, req *ai.ChatCompletionRequest, cfg *ai.ProviderConfig) (*ai.ChatCompletionResponse, error) {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		return nil, fmt.Errorf("generic passthrough: base_url is required")
	}
	baseURL = strings.TrimRight(baseURL, "/")

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("generic passthrough: marshal error: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	g.setAuthHeader(httpReq, cfg)

	resp, err := g.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, &ai.AIError{
			StatusCode: resp.StatusCode,
			Type:       "provider_error",
			Message:    string(respBody),
		}
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Try to extract standard response fields for token tracking
	var result ai.ChatCompletionResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		// If we can't parse it as OpenAI format, wrap it
		result = ai.ChatCompletionResponse{
			Model: req.Model,
			Choices: []ai.Choice{
				{
					Index: 0,
					Message: ai.Message{
						Role:    "assistant",
						Content: json.RawMessage(fmt.Sprintf("%q", string(respBody))),
					},
				},
			},
		}
	}
	return &result, nil
}

// passthroughStream forwards the streaming request as-is.
func (g *Generic) passthroughStream(ctx context.Context, req *ai.ChatCompletionRequest, cfg *ai.ProviderConfig) (ai.StreamReader, error) {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		return nil, fmt.Errorf("generic passthrough: base_url is required")
	}
	baseURL = strings.TrimRight(baseURL, "/")

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("generic passthrough: marshal error: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	g.setAuthHeader(httpReq, cfg)

	resp, err := g.client.Do(httpReq)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		return nil, &ai.AIError{
			StatusCode: resp.StatusCode,
			Type:       "provider_error",
			Message:    string(respBody),
		}
	}

	parser := ai.NewSSEParser(resp.Body, 0)
	return &openAIStreamReader{parser: parser, body: resp.Body}, nil
}

// setAuthHeader applies the appropriate auth header based on config.
func (g *Generic) setAuthHeader(req *http.Request, cfg *ai.ProviderConfig) {
	if cfg.APIKey == "" {
		return
	}
	headerName := cfg.AuthHeader
	if headerName == "" {
		headerName = "Authorization"
	}
	prefix := cfg.AuthPrefix
	if prefix == "" && headerName == "Authorization" {
		prefix = "Bearer"
	}
	if prefix != "" {
		req.Header.Set(headerName, prefix+" "+cfg.APIKey)
	} else {
		req.Header.Set(headerName, cfg.APIKey)
	}
}
