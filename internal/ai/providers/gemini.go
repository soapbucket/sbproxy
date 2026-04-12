// Package providers contains AI provider implementations for routing requests to upstream LLM services.
package providers

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai"
)

const (
	geminiDefaultBaseURL = "https://generativelanguage.googleapis.com/v1beta"
)

func init() {
	ai.RegisterProvider("gemini", NewGemini)
}

// Gemini implements the Provider interface for Google's Gemini API.
type Gemini struct {
	client *http.Client
}

// NewGemini creates a new Gemini provider.
func NewGemini(client *http.Client) ai.Provider {
	return &Gemini{client: client}
}

// Name returns the provider identifier.
func (g *Gemini) Name() string { return "gemini" }

// SupportsStreaming returns true because Gemini supports SSE streaming.
func (g *Gemini) SupportsStreaming() bool { return true }

// SupportsEmbeddings returns true because Gemini supports embeddings.
func (g *Gemini) SupportsEmbeddings() bool { return true }

// ChatCompletion sends a non-streaming chat request to Gemini.
func (g *Gemini) ChatCompletion(ctx context.Context, req *ai.ChatCompletionRequest, cfg *ai.ProviderConfig) (*ai.ChatCompletionResponse, error) {
	model := resolveGeminiModel(cfg.ResolveModel(req.Model))
	geminiReq := convertToGeminiRequest(req, cfg)

	body, err := json.Marshal(geminiReq)
	if err != nil {
		return nil, fmt.Errorf("gemini: marshal request: %w", err)
	}

	baseURL := geminiDefaultBaseURL
	if cfg.BaseURL != "" {
		baseURL = cfg.BaseURL
	}

	url := fmt.Sprintf("%s/models/%s:generateContent?key=%s", baseURL, model, cfg.APIKey)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	setGeminiHeaders(httpReq, cfg)

	resp, err := g.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("gemini: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, extractGeminiError(resp)
	}

	var geminiResp geminiResponse
	if err := json.NewDecoder(resp.Body).Decode(&geminiResp); err != nil {
		return nil, fmt.Errorf("gemini: decode response: %w", err)
	}

	return convertGeminiResponse(&geminiResp, req.Model), nil
}

// ChatCompletionStream sends a streaming chat request to Gemini.
func (g *Gemini) ChatCompletionStream(ctx context.Context, req *ai.ChatCompletionRequest, cfg *ai.ProviderConfig) (ai.StreamReader, error) {
	model := resolveGeminiModel(cfg.ResolveModel(req.Model))
	geminiReq := convertToGeminiRequest(req, cfg)

	body, err := json.Marshal(geminiReq)
	if err != nil {
		return nil, fmt.Errorf("gemini: marshal request: %w", err)
	}

	baseURL := geminiDefaultBaseURL
	if cfg.BaseURL != "" {
		baseURL = cfg.BaseURL
	}

	url := fmt.Sprintf("%s/models/%s:streamGenerateContent?alt=sse&key=%s", baseURL, model, cfg.APIKey)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	setGeminiHeaders(httpReq, cfg)

	resp, err := g.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("gemini: stream request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, extractGeminiError(resp)
	}

	return &geminiStreamReader{
		parser: ai.NewSSEParser(resp.Body, 0),
		body:   resp.Body,
		model:  req.Model,
	}, nil
}

// Embeddings generates embeddings using Gemini.
func (g *Gemini) Embeddings(ctx context.Context, req *ai.EmbeddingRequest, cfg *ai.ProviderConfig) (*ai.EmbeddingResponse, error) {
	model := resolveGeminiModel(cfg.ResolveModel(req.Model))

	// Convert input to text
	inputText := extractEmbeddingInput(req.Input)

	geminiReq := geminiEmbedRequest{
		Model: "models/" + model,
		Content: geminiContent{
			Parts: []geminiPart{{Text: inputText}},
		},
	}

	body, err := json.Marshal(geminiReq)
	if err != nil {
		return nil, fmt.Errorf("gemini: marshal embedding request: %w", err)
	}

	baseURL := geminiDefaultBaseURL
	if cfg.BaseURL != "" {
		baseURL = cfg.BaseURL
	}

	url := fmt.Sprintf("%s/models/%s:embedContent?key=%s", baseURL, model, cfg.APIKey)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	setGeminiHeaders(httpReq, cfg)

	resp, err := g.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("gemini: embedding request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, extractGeminiError(resp)
	}

	var geminiResp geminiEmbedResponse
	if err := json.NewDecoder(resp.Body).Decode(&geminiResp); err != nil {
		return nil, fmt.Errorf("gemini: decode embedding response: %w", err)
	}

	return &ai.EmbeddingResponse{
		Object: "list",
		Data: []ai.EmbeddingData{{
			Object:    "embedding",
			Embedding: geminiResp.Embedding.Values,
			Index:     0,
		}},
		Model: req.Model,
	}, nil
}

// ListModels returns the models available on Gemini.
func (g *Gemini) ListModels(ctx context.Context, cfg *ai.ProviderConfig) ([]ai.ModelInfo, error) {
	baseURL := geminiDefaultBaseURL
	if cfg.BaseURL != "" {
		baseURL = cfg.BaseURL
	}

	url := fmt.Sprintf("%s/models?key=%s", baseURL, cfg.APIKey)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	setGeminiHeaders(httpReq, cfg)

	resp, err := g.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("gemini: list models failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, extractGeminiError(resp)
	}

	var geminiResp geminiModelsResponse
	if err := json.NewDecoder(resp.Body).Decode(&geminiResp); err != nil {
		return nil, fmt.Errorf("gemini: decode models: %w", err)
	}

	models := make([]ai.ModelInfo, 0, len(geminiResp.Models))
	for _, m := range geminiResp.Models {
		// Strip "models/" prefix for the ID
		id := strings.TrimPrefix(m.Name, "models/")
		models = append(models, ai.ModelInfo{
			ID:      id,
			Object:  "model",
			OwnedBy: "google",
		})
	}
	return models, nil
}

// Gemini-specific request/response types

type geminiRequest struct {
	Contents          []geminiContent       `json:"contents"`
	SystemInstruction *geminiContent        `json:"systemInstruction,omitempty"`
	GenerationConfig  *geminiGenerationCfg  `json:"generationConfig,omitempty"`
	Tools             []geminiToolContainer `json:"tools,omitempty"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text             string                `json:"text,omitempty"`
	FunctionCall     *geminiFunctionCall   `json:"functionCall,omitempty"`
	FunctionResponse *geminiToolResponse   `json:"functionResponse,omitempty"`
}

type geminiFunctionCall struct {
	Name string          `json:"name"`
	Args json.RawMessage `json:"args,omitempty"`
}

type geminiToolResponse struct {
	Name     string          `json:"name"`
	Response json.RawMessage `json:"response"`
}

type geminiGenerationCfg struct {
	Temperature    *float64 `json:"temperature,omitempty"`
	TopP           *float64 `json:"topP,omitempty"`
	MaxOutputTokens *int    `json:"maxOutputTokens,omitempty"`
	StopSequences  []string `json:"stopSequences,omitempty"`
}

type geminiToolContainer struct {
	FunctionDeclarations []geminiFunctionDecl `json:"functionDeclarations"`
}

type geminiFunctionDecl struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

type geminiResponse struct {
	Candidates    []geminiCandidate   `json:"candidates"`
	UsageMetadata *geminiUsageMetadata `json:"usageMetadata,omitempty"`
	ModelVersion  string               `json:"modelVersion,omitempty"`
}

type geminiCandidate struct {
	Content      geminiContent `json:"content"`
	FinishReason string        `json:"finishReason"`
}

type geminiUsageMetadata struct {
	PromptTokenCount        int `json:"promptTokenCount"`
	CandidatesTokenCount    int `json:"candidatesTokenCount"`
	TotalTokenCount         int `json:"totalTokenCount"`
	CachedContentTokenCount int `json:"cachedContentTokenCount,omitempty"`
}

type geminiEmbedRequest struct {
	Model   string        `json:"model"`
	Content geminiContent `json:"content"`
}

type geminiEmbedResponse struct {
	Embedding struct {
		Values []float32 `json:"values"`
	} `json:"embedding"`
}

type geminiModelsResponse struct {
	Models []geminiModelInfo `json:"models"`
}

type geminiModelInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type geminiErrorResponse struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}

// resolveGeminiModel ensures the model name does not have the "models/" prefix
// (the prefix is added in URL construction).
func resolveGeminiModel(model string) string {
	return strings.TrimPrefix(model, "models/")
}

func setGeminiHeaders(req *http.Request, cfg *ai.ProviderConfig) {
	req.Header.Set("Content-Type", "application/json")
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}
}

func convertToGeminiRequest(req *ai.ChatCompletionRequest, cfg *ai.ProviderConfig) *geminiRequest {
	gr := &geminiRequest{}

	// Build generation config
	genCfg := &geminiGenerationCfg{
		Temperature: req.Temperature,
		TopP:        req.TopP,
	}
	if req.MaxTokens != nil {
		genCfg.MaxOutputTokens = req.MaxTokens
	} else if req.MaxCompletionTokens != nil {
		genCfg.MaxOutputTokens = req.MaxCompletionTokens
	}

	// Parse stop sequences
	if req.Stop != nil {
		var stops []string
		if err := json.Unmarshal(req.Stop, &stops); err != nil {
			var single string
			if err := json.Unmarshal(req.Stop, &single); err == nil {
				stops = []string{single}
			}
		}
		genCfg.StopSequences = stops
	}

	// Only include generationConfig if something was set
	if genCfg.Temperature != nil || genCfg.TopP != nil || genCfg.MaxOutputTokens != nil || len(genCfg.StopSequences) > 0 {
		gr.GenerationConfig = genCfg
	}

	// Convert messages, extracting system instruction
	var contents []geminiContent
	for _, msg := range req.Messages {
		switch msg.Role {
		case "system":
			text := msg.ContentString()
			if text != "" {
				gr.SystemInstruction = &geminiContent{
					Parts: []geminiPart{{Text: text}},
				}
			}

		case "assistant":
			gc := geminiContent{Role: "model"}
			if len(msg.ToolCalls) > 0 {
				// Assistant message with tool calls
				text := msg.ContentString()
				if text != "" {
					gc.Parts = append(gc.Parts, geminiPart{Text: text})
				}
				for _, tc := range msg.ToolCalls {
					gc.Parts = append(gc.Parts, geminiPart{
						FunctionCall: &geminiFunctionCall{
							Name: tc.Function.Name,
							Args: json.RawMessage(tc.Function.Arguments),
						},
					})
				}
			} else {
				gc.Parts = []geminiPart{{Text: msg.ContentString()}}
			}
			contents = append(contents, gc)

		case "tool":
			// Tool results become user messages with functionResponse parts
			var responseData json.RawMessage
			text := msg.ContentString()
			// Wrap the text in a JSON object for Gemini's expected format
			responseObj := map[string]string{"result": text}
			responseData, _ = json.Marshal(responseObj)
			contents = append(contents, geminiContent{
				Role: "user",
				Parts: []geminiPart{{
					FunctionResponse: &geminiToolResponse{
						Name:     msg.Name,
						Response: responseData,
					},
				}},
			})

		default: // "user" and any other roles
			gc := geminiContent{
				Role:  "user",
				Parts: []geminiPart{{Text: msg.ContentString()}},
			}
			contents = append(contents, gc)
		}
	}
	gr.Contents = contents

	// Convert tools
	if len(req.Tools) > 0 {
		var decls []geminiFunctionDecl
		for _, t := range req.Tools {
			decls = append(decls, geminiFunctionDecl{
				Name:        t.Function.Name,
				Description: t.Function.Description,
				Parameters:  t.Function.Parameters,
			})
		}
		gr.Tools = []geminiToolContainer{{FunctionDeclarations: decls}}
	}

	return gr
}

func convertGeminiResponse(resp *geminiResponse, requestModel string) *ai.ChatCompletionResponse {
	result := &ai.ChatCompletionResponse{
		ID:      fmt.Sprintf("gemini-%d", time.Now().UnixNano()),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   requestModel,
	}

	if resp.UsageMetadata != nil {
		result.Usage = &ai.Usage{
			PromptTokens:       resp.UsageMetadata.PromptTokenCount,
			CompletionTokens:   resp.UsageMetadata.CandidatesTokenCount,
			TotalTokens:        resp.UsageMetadata.TotalTokenCount,
			PromptTokensCached: resp.UsageMetadata.CachedContentTokenCount,
		}
	}

	if len(resp.Candidates) == 0 {
		return result
	}

	for i, candidate := range resp.Candidates {
		choice := ai.Choice{Index: i}

		// Extract text and tool calls from parts
		var textParts []string
		var toolCalls []ai.ToolCall
		for _, part := range candidate.Content.Parts {
			if part.Text != "" {
				textParts = append(textParts, part.Text)
			}
			if part.FunctionCall != nil {
				toolCalls = append(toolCalls, ai.ToolCall{
					ID:   fmt.Sprintf("call_%s_%d", part.FunctionCall.Name, i),
					Type: "function",
					Function: ai.ToolCallFunction{
						Name:      part.FunctionCall.Name,
						Arguments: string(part.FunctionCall.Args),
					},
				})
			}
		}

		content := strings.Join(textParts, "")
		contentJSON, _ := json.Marshal(content)
		choice.Message = ai.Message{
			Role:      "assistant",
			Content:   contentJSON,
			ToolCalls: toolCalls,
		}

		finishReason := mapGeminiFinishReason(candidate.FinishReason)
		choice.FinishReason = &finishReason

		result.Choices = append(result.Choices, choice)
	}

	return result
}

func mapGeminiFinishReason(reason string) string {
	switch reason {
	case "STOP":
		return "stop"
	case "MAX_TOKENS":
		return "length"
	case "SAFETY":
		return "content_filter"
	case "RECITATION":
		return "content_filter"
	case "OTHER":
		return "stop"
	default:
		return "stop"
	}
}

func extractGeminiError(resp *http.Response) *ai.AIError {
	body, _ := io.ReadAll(resp.Body)

	var errResp geminiErrorResponse
	if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error.Message != "" {
		return &ai.AIError{
			StatusCode: resp.StatusCode,
			Type:       errResp.Error.Status,
			Message:    errResp.Error.Message,
		}
	}

	return &ai.AIError{
		StatusCode: resp.StatusCode,
		Type:       "api_error",
		Message:    fmt.Sprintf("Gemini API error: %s", string(body)),
	}
}

// extractEmbeddingInput converts the input field (string or []string) to a single string.
func extractEmbeddingInput(input any) string {
	switch v := input.(type) {
	case string:
		return v
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " ")
	default:
		// Try JSON round-trip for json.RawMessage or similar
		data, err := json.Marshal(input)
		if err != nil {
			return ""
		}
		var s string
		if err := json.Unmarshal(data, &s); err == nil {
			return s
		}
		var arr []string
		if err := json.Unmarshal(data, &arr); err == nil {
			return strings.Join(arr, " ")
		}
		return string(data)
	}
}

// geminiStreamReader converts Gemini SSE events to OpenAI StreamChunks.
type geminiStreamReader struct {
	parser     *ai.SSEParser
	body       io.ReadCloser
	model      string
	chunkID    string
	chunkCount int
}

// Read returns the next chunk from the Gemini stream.
func (r *geminiStreamReader) Read() (*ai.StreamChunk, error) {
	for {
		event, err := r.parser.ReadEvent()
		if err != nil {
			return nil, err
		}

		if ai.IsDone(event.Data) {
			ai.ReleaseSSEEvent(event)
			return nil, io.EOF
		}

		var geminiResp geminiResponse
		if err := json.Unmarshal([]byte(event.Data), &geminiResp); err != nil {
			ai.ReleaseSSEEvent(event)
			continue // skip malformed chunks
		}
		ai.ReleaseSSEEvent(event)

		if r.chunkID == "" {
			r.chunkID = fmt.Sprintf("gemini-stream-%d", time.Now().UnixNano())
		}
		r.chunkCount++

		chunk := &ai.StreamChunk{
			ID:     r.chunkID,
			Object: "chat.completion.chunk",
			Model:  r.model,
		}

		// Map usage metadata
		if geminiResp.UsageMetadata != nil {
			chunk.Usage = &ai.Usage{
				PromptTokens:       geminiResp.UsageMetadata.PromptTokenCount,
				CompletionTokens:   geminiResp.UsageMetadata.CandidatesTokenCount,
				TotalTokens:        geminiResp.UsageMetadata.TotalTokenCount,
				PromptTokensCached: geminiResp.UsageMetadata.CachedContentTokenCount,
			}
		}

		if len(geminiResp.Candidates) == 0 {
			// Usage-only chunk (can happen at end of stream)
			if chunk.Usage != nil {
				chunk.Choices = []ai.StreamChoice{{Index: 0, Delta: ai.StreamDelta{}}}
				return chunk, nil
			}
			continue
		}

		candidate := geminiResp.Candidates[0]

		// Build delta from parts
		var textParts []string
		var toolCalls []ai.ToolCallDelta
		for _, part := range candidate.Content.Parts {
			if part.Text != "" {
				textParts = append(textParts, part.Text)
			}
			if part.FunctionCall != nil {
				toolCalls = append(toolCalls, ai.ToolCallDelta{
					Index: len(toolCalls),
					ID:    fmt.Sprintf("call_%s_%d", part.FunctionCall.Name, r.chunkCount),
					Type:  "function",
					Function: &ai.ToolCallFunction{
						Name:      part.FunctionCall.Name,
						Arguments: string(part.FunctionCall.Args),
					},
				})
			}
		}

		delta := ai.StreamDelta{}
		if r.chunkCount == 1 {
			delta.Role = "assistant"
		}
		if len(textParts) > 0 {
			text := strings.Join(textParts, "")
			delta.Content = &text
		}
		if len(toolCalls) > 0 {
			delta.ToolCalls = toolCalls
		}

		streamChoice := ai.StreamChoice{
			Index: 0,
			Delta: delta,
		}

		if candidate.FinishReason != "" {
			fr := mapGeminiFinishReason(candidate.FinishReason)
			streamChoice.FinishReason = &fr
		}

		chunk.Choices = []ai.StreamChoice{streamChoice}
		return chunk, nil
	}
}

// Close releases resources held by the geminiStreamReader.
func (r *geminiStreamReader) Close() error {
	r.parser.Close()
	return r.body.Close()
}
