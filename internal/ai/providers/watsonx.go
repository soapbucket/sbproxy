// Package providers contains AI provider implementations for routing requests to upstream LLM services.
package providers

import (
	"bytes"
	"context"
	"fmt"
	json "github.com/goccy/go-json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai"
)

const (
	watsonxIAMTokenURL    = "https://iam.cloud.ibm.com/identity/token"
	watsonxDefaultBaseURL = "https://us-south.ml.cloud.ibm.com"
	// Refresh the IAM token at 80% of its TTL to avoid using expired tokens.
	watsonxTokenRefreshRatio = 0.8
)

func init() {
	ai.RegisterProvider("watsonx", NewWatsonx)
}

// Watsonx implements the Provider interface for IBM watsonx.ai.
// It handles IAM token exchange and caches the bearer token, refreshing it
// before expiry at 80% of the token's TTL.
type Watsonx struct {
	client *http.Client

	mu          sync.Mutex
	cachedToken string
	tokenExpiry time.Time
}

// NewWatsonx creates and initializes a new Watsonx provider.
func NewWatsonx(client *http.Client) ai.Provider {
	return &Watsonx{client: client}
}

// Name returns the provider name.
func (w *Watsonx) Name() string { return "watsonx" }

// SupportsStreaming returns true because watsonx supports SSE streaming.
func (w *Watsonx) SupportsStreaming() bool { return true }

// SupportsEmbeddings returns true because watsonx supports embedding models.
func (w *Watsonx) SupportsEmbeddings() bool { return true }

// ChatCompletion sends a non-streaming chat completion request to watsonx.
func (w *Watsonx) ChatCompletion(ctx context.Context, req *ai.ChatCompletionRequest, cfg *ai.ProviderConfig) (*ai.ChatCompletionResponse, error) {
	token, err := w.getToken(ctx, cfg)
	if err != nil {
		return nil, err
	}

	httpReq, err := w.buildChatRequest(ctx, req, cfg, false)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := w.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("watsonx: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, &ai.AIError{
			StatusCode: resp.StatusCode,
			Type:       "watsonx_error",
			Message:    string(body),
		}
	}

	var result ai.ChatCompletionResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("watsonx: decode response: %w", err)
	}
	return &result, nil
}

// ChatCompletionStream sends a streaming chat completion request to watsonx.
func (w *Watsonx) ChatCompletionStream(ctx context.Context, req *ai.ChatCompletionRequest, cfg *ai.ProviderConfig) (ai.StreamReader, error) {
	token, err := w.getToken(ctx, cfg)
	if err != nil {
		return nil, err
	}

	httpReq, err := w.buildChatRequest(ctx, req, cfg, true)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := w.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("watsonx: stream request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return nil, &ai.AIError{
			StatusCode: resp.StatusCode,
			Type:       "watsonx_error",
			Message:    string(body),
		}
	}

	return &openAIStreamReader{
		parser: ai.NewSSEParser(resp.Body, 0),
		body:   resp.Body,
	}, nil
}

// Embeddings sends an embedding request to watsonx.
func (w *Watsonx) Embeddings(ctx context.Context, req *ai.EmbeddingRequest, cfg *ai.ProviderConfig) (*ai.EmbeddingResponse, error) {
	token, err := w.getToken(ctx, cfg)
	if err != nil {
		return nil, err
	}

	baseURL := watsonxDefaultBaseURL
	if cfg.BaseURL != "" {
		baseURL = cfg.BaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("watsonx: marshal embedding request: %w", err)
	}

	endpoint := baseURL + "/ml/v1/text/embeddings"
	if cfg.ProjectID != "" {
		endpoint += "?project_id=" + url.QueryEscape(cfg.ProjectID)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := w.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("watsonx: embedding request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, &ai.AIError{
			StatusCode: resp.StatusCode,
			Type:       "watsonx_error",
			Message:    string(respBody),
		}
	}

	var result ai.EmbeddingResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("watsonx: decode embedding response: %w", err)
	}
	return &result, nil
}

// ListModels returns nil because watsonx model listing requires separate API handling.
func (w *Watsonx) ListModels(_ context.Context, _ *ai.ProviderConfig) ([]ai.ModelInfo, error) {
	return nil, nil
}

// buildChatRequest constructs an OpenAI-format HTTP request for the watsonx chat endpoint.
// The project_id query parameter is appended when configured.
func (w *Watsonx) buildChatRequest(ctx context.Context, req *ai.ChatCompletionRequest, cfg *ai.ProviderConfig, stream bool) (*http.Request, error) {
	baseURL := watsonxDefaultBaseURL
	if cfg.BaseURL != "" {
		baseURL = cfg.BaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")

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
		return nil, fmt.Errorf("watsonx: marshal request: %w", err)
	}

	endpoint := baseURL + "/ml/v1/text/chat"
	if cfg.ProjectID != "" {
		endpoint += "?project_id=" + url.QueryEscape(cfg.ProjectID)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	return httpReq, nil
}

// iamTokenResponse represents the response from the IBM IAM token endpoint.
type iamTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// getToken returns a valid IAM bearer token, fetching or refreshing as needed.
// It uses a mutex to prevent concurrent token refreshes.
func (w *Watsonx) getToken(ctx context.Context, cfg *ai.ProviderConfig) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.cachedToken != "" && time.Now().Before(w.tokenExpiry) {
		return w.cachedToken, nil
	}

	if cfg.APIKey == "" {
		return "", fmt.Errorf("watsonx: api_key is required for IAM token exchange")
	}

	formData := url.Values{
		"grant_type": {"urn:ibm:params:oauth:grant-type:apikey"},
		"apikey":     {cfg.APIKey},
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, watsonxIAMTokenURL,
		strings.NewReader(formData.Encode()))
	if err != nil {
		return "", fmt.Errorf("watsonx: build token request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := w.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("watsonx: token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("watsonx: IAM token exchange failed (status %d): %s", resp.StatusCode, string(body))
	}

	var tokenResp iamTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("watsonx: decode token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("watsonx: empty access_token in IAM response")
	}

	w.cachedToken = tokenResp.AccessToken
	// Refresh at 80% of TTL to avoid expiry during a request
	ttl := time.Duration(float64(tokenResp.ExpiresIn)*watsonxTokenRefreshRatio) * time.Second
	w.tokenExpiry = time.Now().Add(ttl)

	return w.cachedToken, nil
}
