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
	cohereDefaultBaseURL = "https://api.cohere.com/v2"
)

func init() {
	ai.RegisterProvider("cohere", NewCohere)
}

// Cohere implements the Provider interface for Cohere's v2 API.
type Cohere struct {
	client *http.Client
}

// NewCohere creates and initializes a new Cohere provider.
func NewCohere(client *http.Client) ai.Provider {
	return &Cohere{client: client}
}

// Name returns the provider name.
func (c *Cohere) Name() string { return "cohere" }

// SupportsStreaming returns true since Cohere supports SSE streaming.
func (c *Cohere) SupportsStreaming() bool { return true }

// SupportsEmbeddings returns true since Cohere supports embeddings.
func (c *Cohere) SupportsEmbeddings() bool { return true }

// ChatCompletion sends a non-streaming chat request to Cohere.
func (c *Cohere) ChatCompletion(ctx context.Context, req *ai.ChatCompletionRequest, cfg *ai.ProviderConfig) (*ai.ChatCompletionResponse, error) {
	httpReq, err := c.buildChatRequest(ctx, req, cfg, false)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("cohere: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, extractCohereError(resp)
	}

	var cohereResp cohereResponse
	if err := json.NewDecoder(resp.Body).Decode(&cohereResp); err != nil {
		return nil, fmt.Errorf("cohere: decode response: %w", err)
	}

	return convertCohereResponse(&cohereResp, req.Model), nil
}

// ChatCompletionStream sends a streaming chat request to Cohere.
func (c *Cohere) ChatCompletionStream(ctx context.Context, req *ai.ChatCompletionRequest, cfg *ai.ProviderConfig) (ai.StreamReader, error) {
	httpReq, err := c.buildChatRequest(ctx, req, cfg, true)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("cohere: stream request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, extractCohereError(resp)
	}

	return &cohereStreamReader{
		parser: ai.NewSSEParser(resp.Body, 0),
		body:   resp.Body,
		model:  req.Model,
	}, nil
}

// Embeddings generates embeddings using Cohere's API.
func (c *Cohere) Embeddings(ctx context.Context, req *ai.EmbeddingRequest, cfg *ai.ProviderConfig) (*ai.EmbeddingResponse, error) {
	cohereReq := convertToCohereEmbeddingRequest(req, cfg)

	body, err := json.Marshal(cohereReq)
	if err != nil {
		return nil, fmt.Errorf("cohere: marshal embedding request: %w", err)
	}

	baseURL := cohereDefaultBaseURL
	if cfg.BaseURL != "" {
		baseURL = cfg.BaseURL
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/embed", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	setCohereHeaders(httpReq, cfg)

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("cohere: embedding request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, extractCohereError(resp)
	}

	var cohereResp cohereEmbeddingResponse
	if err := json.NewDecoder(resp.Body).Decode(&cohereResp); err != nil {
		return nil, fmt.Errorf("cohere: decode embedding response: %w", err)
	}

	return convertCohereEmbeddingResponse(&cohereResp, req.Model), nil
}

// ListModels returns available models from Cohere's API.
func (c *Cohere) ListModels(ctx context.Context, cfg *ai.ProviderConfig) ([]ai.ModelInfo, error) {
	baseURL := cohereDefaultBaseURL
	if cfg.BaseURL != "" {
		baseURL = cfg.BaseURL
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/models", nil)
	if err != nil {
		return nil, err
	}
	setCohereHeaders(httpReq, cfg)

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("cohere: list models failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, extractCohereError(resp)
	}

	var cohereResp cohereModelsResponse
	if err := json.NewDecoder(resp.Body).Decode(&cohereResp); err != nil {
		return nil, fmt.Errorf("cohere: decode models: %w", err)
	}

	models := make([]ai.ModelInfo, 0, len(cohereResp.Models))
	for _, m := range cohereResp.Models {
		models = append(models, ai.ModelInfo{
			ID:      m.Name,
			Object:  "model",
			OwnedBy: "cohere",
		})
	}
	return models, nil
}

// Cohere-specific types

type cohereChatRequest struct {
	Model       string           `json:"model"`
	Messages    []cohereMessage  `json:"messages"`
	Temperature *float64         `json:"temperature,omitempty"`
	MaxTokens   *int             `json:"max_tokens,omitempty"`
	TopP        *float64         `json:"p,omitempty"`
	Stop        []string         `json:"stop_sequences,omitempty"`
	Stream      bool             `json:"stream,omitempty"`
	Tools       []cohereTool     `json:"tools,omitempty"`
	Seed        *int64           `json:"seed,omitempty"`
}

type cohereMessage struct {
	Role      string          `json:"role"`
	Content   any             `json:"content"`
	ToolCalls []cohereToolCall `json:"tool_calls,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
}

type cohereToolCall struct {
	ID       string               `json:"id"`
	Type     string               `json:"type"`
	Function cohereToolCallFunction `json:"function"`
}

type cohereToolCallFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type cohereTool struct {
	Type     string             `json:"type"`
	Function cohereToolFunction `json:"function"`
}

type cohereToolFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

type cohereResponse struct {
	ID           string               `json:"id"`
	Message      cohereResponseMessage `json:"message"`
	FinishReason string               `json:"finish_reason"`
	Usage        cohereUsage          `json:"usage"`
	Model        string               `json:"model,omitempty"`
}

type cohereResponseMessage struct {
	Role      string               `json:"role"`
	Content   []cohereContentBlock `json:"content,omitempty"`
	ToolCalls []cohereToolCall     `json:"tool_calls,omitempty"`
}

type cohereContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type cohereUsage struct {
	BilledUnits *cohereBilledUnits `json:"billed_units,omitempty"`
	Tokens      *cohereTokens      `json:"tokens,omitempty"`
}

type cohereBilledUnits struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type cohereTokens struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type cohereEmbeddingRequest struct {
	Texts          []string `json:"texts"`
	Model          string   `json:"model"`
	InputType      string   `json:"input_type"`
	EmbeddingTypes []string `json:"embedding_types"`
}

type cohereEmbeddingResponse struct {
	ID         string                 `json:"id"`
	Embeddings cohereEmbeddingsData   `json:"embeddings"`
	Meta       *cohereEmbeddingMeta   `json:"meta,omitempty"`
}

type cohereEmbeddingsData struct {
	Float [][]float32 `json:"float"`
}

type cohereEmbeddingMeta struct {
	BilledUnits *cohereBilledUnits `json:"billed_units,omitempty"`
}

type cohereModelsResponse struct {
	Models []cohereModel `json:"models"`
}

type cohereModel struct {
	Name string `json:"name"`
}

// Streaming event types

type cohereStreamEvent struct {
	Type string `json:"type"`
}

type cohereStreamMessageStart struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Delta struct {
		Message struct {
			Role string `json:"role"`
		} `json:"message"`
	} `json:"delta"`
}

type cohereStreamContentDelta struct {
	Type  string `json:"type"`
	Index int    `json:"index"`
	Delta struct {
		Message struct {
			Content struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"message"`
	} `json:"delta"`
}

type cohereStreamToolCallDelta struct {
	Type  string `json:"type"`
	Index int    `json:"index"`
	Delta struct {
		Message struct {
			ToolCalls struct {
				Function struct {
					Name      string `json:"name,omitempty"`
					Arguments string `json:"arguments,omitempty"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
	} `json:"delta"`
}

type cohereStreamToolCallStart struct {
	Type  string `json:"type"`
	Index int    `json:"index"`
	Delta struct {
		Message struct {
			ToolCalls struct {
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
	} `json:"delta"`
}

type cohereStreamMessageEnd struct {
	Type  string `json:"type"`
	ID    string `json:"id"`
	Delta struct {
		FinishReason string      `json:"finish_reason"`
		Usage        cohereUsage `json:"usage"`
	} `json:"delta"`
}

func (c *Cohere) buildChatRequest(ctx context.Context, req *ai.ChatCompletionRequest, cfg *ai.ProviderConfig, stream bool) (*http.Request, error) {
	cohereReq := convertToCohereChatRequest(req, cfg)
	cohereReq.Stream = stream

	body, err := json.Marshal(cohereReq)
	if err != nil {
		return nil, fmt.Errorf("cohere: marshal request: %w", err)
	}

	baseURL := cohereDefaultBaseURL
	if cfg.BaseURL != "" {
		baseURL = cfg.BaseURL
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/chat", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	setCohereHeaders(httpReq, cfg)

	return httpReq, nil
}

func setCohereHeaders(req *http.Request, cfg *ai.ProviderConfig) {
	req.Header.Set("Content-Type", "application/json")
	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}
}

func convertToCohereChatRequest(req *ai.ChatCompletionRequest, cfg *ai.ProviderConfig) *cohereChatRequest {
	cr := &cohereChatRequest{
		Model:       cfg.ResolveModel(req.Model),
		Temperature: req.Temperature,
		TopP:        req.TopP,
		Seed:        req.Seed,
	}

	if req.MaxTokens != nil {
		cr.MaxTokens = req.MaxTokens
	} else if req.MaxCompletionTokens != nil {
		cr.MaxTokens = req.MaxCompletionTokens
	}

	// Convert stop sequences
	if req.Stop != nil {
		var stops []string
		if err := json.Unmarshal(req.Stop, &stops); err != nil {
			var single string
			if err := json.Unmarshal(req.Stop, &single); err == nil {
				stops = []string{single}
			}
		}
		cr.Stop = stops
	}

	// Convert messages
	for _, msg := range req.Messages {
		cm := cohereMessage{Role: msg.Role}

		if msg.Role == "tool" {
			cm.Role = "tool"
			cm.Content = msg.ContentString()
			cm.ToolCallID = msg.ToolCallID
			cr.Messages = append(cr.Messages, cm)
			continue
		}

		if msg.Role == "assistant" && len(msg.ToolCalls) > 0 {
			var toolCalls []cohereToolCall
			for _, tc := range msg.ToolCalls {
				toolCalls = append(toolCalls, cohereToolCall{
					ID:   tc.ID,
					Type: "function",
					Function: cohereToolCallFunction{
						Name:      tc.Function.Name,
						Arguments: tc.Function.Arguments,
					},
				})
			}
			cm.ToolCalls = toolCalls
			content := msg.ContentString()
			if content != "" {
				cm.Content = content
			}
			cr.Messages = append(cr.Messages, cm)
			continue
		}

		cm.Content = msg.ContentString()
		cr.Messages = append(cr.Messages, cm)
	}

	// Convert tools
	for _, t := range req.Tools {
		cr.Tools = append(cr.Tools, cohereTool{
			Type: "function",
			Function: cohereToolFunction{
				Name:        t.Function.Name,
				Description: t.Function.Description,
				Parameters:  t.Function.Parameters,
			},
		})
	}

	return cr
}

func convertCohereResponse(resp *cohereResponse, requestModel string) *ai.ChatCompletionResponse {
	model := resp.Model
	if model == "" {
		model = requestModel
	}

	choice := ai.Choice{Index: 0}

	// Extract text content
	var contentParts []string
	for _, block := range resp.Message.Content {
		if block.Type == "text" {
			contentParts = append(contentParts, block.Text)
		}
	}

	content := strings.Join(contentParts, "")
	contentJSON, _ := json.Marshal(content)
	choice.Message = ai.Message{
		Role:    "assistant",
		Content: contentJSON,
	}

	// Convert tool calls
	if len(resp.Message.ToolCalls) > 0 {
		var toolCalls []ai.ToolCall
		for _, tc := range resp.Message.ToolCalls {
			toolCalls = append(toolCalls, ai.ToolCall{
				ID:   tc.ID,
				Type: "function",
				Function: ai.ToolCallFunction{
					Name:      tc.Function.Name,
					Arguments: tc.Function.Arguments,
				},
			})
		}
		choice.Message.ToolCalls = toolCalls
	}

	finishReason := mapCohereFinishReason(resp.FinishReason)
	choice.FinishReason = &finishReason

	usage := convertCohereUsage(&resp.Usage)

	return &ai.ChatCompletionResponse{
		ID:      resp.ID,
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   model,
		Choices: []ai.Choice{choice},
		Usage:   usage,
	}
}

func mapCohereFinishReason(reason string) string {
	switch reason {
	case "COMPLETE":
		return "stop"
	case "MAX_TOKENS":
		return "length"
	case "TOOL_CALL":
		return "tool_calls"
	case "ERROR":
		return "stop"
	case "STOP_SEQUENCE":
		return "stop"
	default:
		return reason
	}
}

func convertCohereUsage(usage *cohereUsage) *ai.Usage {
	u := &ai.Usage{}
	if usage.Tokens != nil {
		u.PromptTokens = usage.Tokens.InputTokens
		u.CompletionTokens = usage.Tokens.OutputTokens
		u.TotalTokens = usage.Tokens.InputTokens + usage.Tokens.OutputTokens
	} else if usage.BilledUnits != nil {
		u.PromptTokens = usage.BilledUnits.InputTokens
		u.CompletionTokens = usage.BilledUnits.OutputTokens
		u.TotalTokens = usage.BilledUnits.InputTokens + usage.BilledUnits.OutputTokens
	}
	return u
}

func convertToCohereEmbeddingRequest(req *ai.EmbeddingRequest, cfg *ai.ProviderConfig) *cohereEmbeddingRequest {
	cr := &cohereEmbeddingRequest{
		Model:          cfg.ResolveModel(req.Model),
		InputType:      "search_document",
		EmbeddingTypes: []string{"float"},
	}

	// Convert input to texts slice
	switch v := req.Input.(type) {
	case string:
		cr.Texts = []string{v}
	case []string:
		cr.Texts = v
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				cr.Texts = append(cr.Texts, s)
			}
		}
	}

	return cr
}

func convertCohereEmbeddingResponse(resp *cohereEmbeddingResponse, requestModel string) *ai.EmbeddingResponse {
	result := &ai.EmbeddingResponse{
		Object: "list",
		Model:  requestModel,
	}

	for i, emb := range resp.Embeddings.Float {
		result.Data = append(result.Data, ai.EmbeddingData{
			Object:    "embedding",
			Embedding: emb,
			Index:     i,
		})
	}

	if resp.Meta != nil && resp.Meta.BilledUnits != nil {
		result.Usage = &ai.EmbeddingUsage{
			PromptTokens: resp.Meta.BilledUnits.InputTokens,
			TotalTokens:  resp.Meta.BilledUnits.InputTokens,
		}
	}

	return result
}

func extractCohereError(resp *http.Response) *ai.AIError {
	body, _ := io.ReadAll(resp.Body)

	var errResp struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &errResp); err == nil && errResp.Message != "" {
		return &ai.AIError{
			StatusCode: resp.StatusCode,
			Type:       "api_error",
			Message:    errResp.Message,
		}
	}

	return &ai.AIError{
		StatusCode: resp.StatusCode,
		Type:       "api_error",
		Message:    fmt.Sprintf("Cohere API error: %s", string(body)),
	}
}

// cohereStreamReader converts Cohere SSE events to OpenAI StreamChunks.
type cohereStreamReader struct {
	parser *ai.SSEParser
	body   io.ReadCloser
	model  string
	msgID  string
}

// Read returns the next StreamChunk from the Cohere SSE stream.
func (r *cohereStreamReader) Read() (*ai.StreamChunk, error) {
	for {
		event, err := r.parser.ReadEvent()
		if err != nil {
			return nil, err
		}

		eventType := event.Event

		// Determine event type from the event field or from the data payload
		if eventType == "" {
			var evt cohereStreamEvent
			if err := json.Unmarshal([]byte(event.Data), &evt); err == nil {
				eventType = evt.Type
			}
		}

		switch eventType {
		case "message-start":
			var msg cohereStreamMessageStart
			if err := json.Unmarshal([]byte(event.Data), &msg); err != nil {
				ai.ReleaseSSEEvent(event)
				continue
			}
			r.msgID = msg.ID
			ai.ReleaseSSEEvent(event)

			role := msg.Delta.Message.Role
			if role == "" {
				role = "assistant"
			}
			return &ai.StreamChunk{
				ID:     r.msgID,
				Object: "chat.completion.chunk",
				Model:  r.model,
				Choices: []ai.StreamChoice{{
					Index: 0,
					Delta: ai.StreamDelta{Role: role},
				}},
			}, nil

		case "content-delta":
			var cd cohereStreamContentDelta
			if err := json.Unmarshal([]byte(event.Data), &cd); err != nil {
				ai.ReleaseSSEEvent(event)
				continue
			}
			ai.ReleaseSSEEvent(event)

			text := cd.Delta.Message.Content.Text
			return &ai.StreamChunk{
				ID:     r.msgID,
				Object: "chat.completion.chunk",
				Model:  r.model,
				Choices: []ai.StreamChoice{{
					Index: 0,
					Delta: ai.StreamDelta{Content: &text},
				}},
			}, nil

		case "tool-call-start":
			var tcs cohereStreamToolCallStart
			if err := json.Unmarshal([]byte(event.Data), &tcs); err != nil {
				ai.ReleaseSSEEvent(event)
				continue
			}
			ai.ReleaseSSEEvent(event)

			return &ai.StreamChunk{
				ID:     r.msgID,
				Object: "chat.completion.chunk",
				Model:  r.model,
				Choices: []ai.StreamChoice{{
					Index: 0,
					Delta: ai.StreamDelta{
						ToolCalls: []ai.ToolCallDelta{{
							Index: tcs.Index,
							ID:    tcs.Delta.Message.ToolCalls.ID,
							Type:  "function",
							Function: &ai.ToolCallFunction{
								Name:      tcs.Delta.Message.ToolCalls.Function.Name,
								Arguments: tcs.Delta.Message.ToolCalls.Function.Arguments,
							},
						}},
					},
				}},
			}, nil

		case "tool-call-delta":
			var tcd cohereStreamToolCallDelta
			if err := json.Unmarshal([]byte(event.Data), &tcd); err != nil {
				ai.ReleaseSSEEvent(event)
				continue
			}
			ai.ReleaseSSEEvent(event)

			return &ai.StreamChunk{
				ID:     r.msgID,
				Object: "chat.completion.chunk",
				Model:  r.model,
				Choices: []ai.StreamChoice{{
					Index: 0,
					Delta: ai.StreamDelta{
						ToolCalls: []ai.ToolCallDelta{{
							Index: tcd.Index,
							Function: &ai.ToolCallFunction{
								Arguments: tcd.Delta.Message.ToolCalls.Function.Arguments,
							},
						}},
					},
				}},
			}, nil

		case "content-start", "content-end", "tool-call-end":
			ai.ReleaseSSEEvent(event)
			continue

		case "message-end":
			var me cohereStreamMessageEnd
			if err := json.Unmarshal([]byte(event.Data), &me); err != nil {
				ai.ReleaseSSEEvent(event)
				return nil, io.EOF
			}
			ai.ReleaseSSEEvent(event)

			finishReason := mapCohereFinishReason(me.Delta.FinishReason)
			usage := convertCohereUsage(&me.Delta.Usage)

			return &ai.StreamChunk{
				ID:     r.msgID,
				Object: "chat.completion.chunk",
				Model:  r.model,
				Choices: []ai.StreamChoice{{
					Index:        0,
					Delta:        ai.StreamDelta{},
					FinishReason: &finishReason,
				}},
				Usage: usage,
			}, nil

		default:
			ai.ReleaseSSEEvent(event)
			if ai.IsDone(event.Data) {
				return nil, io.EOF
			}
			continue
		}
	}
}

// Close releases resources held by the cohereStreamReader.
func (r *cohereStreamReader) Close() error {
	r.parser.Close()
	return r.body.Close()
}
