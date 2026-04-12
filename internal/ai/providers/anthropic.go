// Package providers contains AI provider implementations for routing requests to upstream LLM services.
package providers

import (
	"bytes"
	"context"
	json "github.com/goccy/go-json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/soapbucket/sbproxy/internal/ai"
)

const (
	anthropicDefaultBaseURL = "https://api.anthropic.com/v1"
	anthropicAPIVersion     = "2023-06-01"
	anthropicDefaultMaxTokens = 4096
)

func init() {
	ai.RegisterProvider("anthropic", NewAnthropic)
}

// Anthropic implements the Provider interface for Anthropic's API.
type Anthropic struct {
	client *http.Client
}

// NewAnthropic creates and initializes a new Anthropic.
func NewAnthropic(client *http.Client) ai.Provider {
	return &Anthropic{client: client}
}

// Name performs the name operation on the Anthropic.
func (a *Anthropic) Name() string            { return "anthropic" }
// SupportsStreaming performs the supports streaming operation on the Anthropic.
func (a *Anthropic) SupportsStreaming() bool  { return true }
// SupportsEmbeddings performs the supports embeddings operation on the Anthropic.
func (a *Anthropic) SupportsEmbeddings() bool { return false }

// ChatCompletion performs the chat completion operation on the Anthropic.
func (a *Anthropic) ChatCompletion(ctx context.Context, req *ai.ChatCompletionRequest, cfg *ai.ProviderConfig) (*ai.ChatCompletionResponse, error) {
	httpReq, err := a.buildRequest(ctx, req, cfg, false)
	if err != nil {
		return nil, err
	}

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("anthropic: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, extractAnthropicError(resp)
	}

	var anthropicResp anthropicResponse
	if err := json.NewDecoder(resp.Body).Decode(&anthropicResp); err != nil {
		return nil, fmt.Errorf("anthropic: decode response: %w", err)
	}

	return convertAnthropicResponse(&anthropicResp, req.Model), nil
}

// ChatCompletionStream performs the chat completion stream operation on the Anthropic.
func (a *Anthropic) ChatCompletionStream(ctx context.Context, req *ai.ChatCompletionRequest, cfg *ai.ProviderConfig) (ai.StreamReader, error) {
	httpReq, err := a.buildRequest(ctx, req, cfg, true)
	if err != nil {
		return nil, err
	}

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("anthropic: stream request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, extractAnthropicError(resp)
	}

	return &anthropicStreamReader{
		parser: ai.NewSSEParser(resp.Body, 0),
		body:   resp.Body,
		model:  req.Model,
	}, nil
}

// Embeddings performs the embeddings operation on the Anthropic.
func (a *Anthropic) Embeddings(_ context.Context, _ *ai.EmbeddingRequest, _ *ai.ProviderConfig) (*ai.EmbeddingResponse, error) {
	return nil, fmt.Errorf("anthropic: embeddings not supported")
}

// ListModels performs the list models operation on the Anthropic.
func (a *Anthropic) ListModels(_ context.Context, _ *ai.ProviderConfig) ([]ai.ModelInfo, error) {
	// Anthropic doesn't have a models endpoint; return static list
	models := []ai.ModelInfo{
		{ID: "claude-opus-4-20250514", Object: "model", OwnedBy: "anthropic"},
		{ID: "claude-sonnet-4-20250514", Object: "model", OwnedBy: "anthropic"},
		{ID: "claude-sonnet-4-5-20250929", Object: "model", OwnedBy: "anthropic"},
		{ID: "claude-haiku-4-5-20251001", Object: "model", OwnedBy: "anthropic"},
		{ID: "claude-3-5-sonnet-20241022", Object: "model", OwnedBy: "anthropic"},
		{ID: "claude-3-5-haiku-20241022", Object: "model", OwnedBy: "anthropic"},
	}
	return models, nil
}

// Anthropic-specific request/response types

type anthropicRequest struct {
	Model       string             `json:"model"`
	Messages    []anthropicMessage `json:"messages"`
	System      any                `json:"system,omitempty"` // string or []anthropicContentBlock (for cache_control)
	MaxTokens   int                `json:"max_tokens"`
	Temperature *float64           `json:"temperature,omitempty"`
	TopP        *float64           `json:"top_p,omitempty"`
	Stream      bool               `json:"stream,omitempty"`
	StopSeqs    []string           `json:"stop_sequences,omitempty"`
	Tools       []anthropicTool    `json:"tools,omitempty"`
	ToolChoice  any                `json:"tool_choice,omitempty"`
	Metadata    *anthropicMetadata `json:"metadata,omitempty"`
	Thinking    *anthropicThinking `json:"thinking,omitempty"`
}

type anthropicThinking struct {
	Type         string `json:"type"`
	BudgetTokens int    `json:"budget_tokens"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"` // string or []anthropicContentBlock
}

type anthropicContentBlock struct {
	Type         string                  `json:"type"`
	Text         string                  `json:"text,omitempty"`
	ID           string                  `json:"id,omitempty"`
	Name         string                  `json:"name,omitempty"`
	Input        json.RawMessage         `json:"input,omitempty"`
	Source       any                     `json:"source,omitempty"`
	ToolUseID    string                  `json:"tool_use_id,omitempty"`
	Content      any                     `json:"content,omitempty"`
	CacheControl *ai.CacheControlConfig  `json:"cache_control,omitempty"`
	Thinking     string                  `json:"thinking,omitempty"`
	Signature    string                  `json:"signature,omitempty"`
}

type anthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type anthropicMetadata struct {
	UserID string `json:"user_id,omitempty"`
}

type anthropicResponse struct {
	ID           string                  `json:"id"`
	Type         string                  `json:"type"`
	Role         string                  `json:"role"`
	Content      []anthropicContentBlock `json:"content"`
	Model        string                  `json:"model"`
	StopReason   string                  `json:"stop_reason"`
	StopSequence *string                 `json:"stop_sequence"`
	Usage        anthropicUsage          `json:"usage"`
}

type anthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	CacheCreation int `json:"cache_creation_input_tokens,omitempty"`
	CacheRead    int `json:"cache_read_input_tokens,omitempty"`
}

func (a *Anthropic) buildRequest(ctx context.Context, req *ai.ChatCompletionRequest, cfg *ai.ProviderConfig, stream bool) (*http.Request, error) {
	anthropicReq := convertToAnthropicRequest(req, cfg)
	anthropicReq.Stream = stream

	body, err := json.Marshal(anthropicReq)
	if err != nil {
		return nil, fmt.Errorf("anthropic: marshal request: %w", err)
	}

	baseURL := anthropicDefaultBaseURL
	if cfg.BaseURL != "" {
		baseURL = cfg.BaseURL
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/messages", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("anthropic-version", anthropicAPIVersion)
	if cfg.APIKey != "" {
		httpReq.Header.Set("x-api-key", cfg.APIKey)
	}
	for k, v := range cfg.Headers {
		httpReq.Header.Set(k, v)
	}

	return httpReq, nil
}

func convertToAnthropicRequest(req *ai.ChatCompletionRequest, cfg *ai.ProviderConfig) *anthropicRequest {
	ar := &anthropicRequest{
		Model:       cfg.ResolveModel(req.Model),
		Temperature: req.Temperature,
		TopP:        req.TopP,
	}

	// max_tokens is required for Anthropic
	if req.MaxTokens != nil {
		ar.MaxTokens = *req.MaxTokens
	} else if req.MaxCompletionTokens != nil {
		ar.MaxTokens = *req.MaxCompletionTokens
	} else {
		ar.MaxTokens = anthropicDefaultMaxTokens
	}

	// Extract system message
	var messages []anthropicMessage
	for _, msg := range req.Messages {
		if msg.Role == "system" {
			ar.System = msg.ContentString()
			continue
		}

		am := anthropicMessage{Role: msg.Role}

		// Convert tool responses
		if msg.Role == "tool" {
			am.Role = "user"
			am.Content = []anthropicContentBlock{{
				Type:      "tool_result",
				ToolUseID: msg.ToolCallID,
				Content:   msg.ContentString(),
			}}
			messages = append(messages, am)
			continue
		}

		// Convert assistant messages with tool calls
		if msg.Role == "assistant" && len(msg.ToolCalls) > 0 {
			var blocks []anthropicContentBlock
			content := msg.ContentString()
			if content != "" {
				blocks = append(blocks, anthropicContentBlock{Type: "text", Text: content})
			}
			for _, tc := range msg.ToolCalls {
				blocks = append(blocks, anthropicContentBlock{
					Type:  "tool_use",
					ID:    tc.ID,
					Name:  tc.Function.Name,
					Input: json.RawMessage(tc.Function.Arguments),
				})
			}
			am.Content = blocks
			messages = append(messages, am)
			continue
		}

		// Regular messages — pass content through
		am.Content = msg.ContentString()
		messages = append(messages, am)
	}
	ar.Messages = messages

	// Convert stop sequences
	if req.Stop != nil {
		var stops []string
		if err := json.Unmarshal(req.Stop, &stops); err != nil {
			var single string
			if err := json.Unmarshal(req.Stop, &single); err == nil {
				stops = []string{single}
			}
		}
		ar.StopSeqs = stops
	}

	// Convert tools
	if len(req.Tools) > 0 {
		for _, t := range req.Tools {
			ar.Tools = append(ar.Tools, anthropicTool{
				Name:        t.Function.Name,
				Description: t.Function.Description,
				InputSchema: t.Function.Parameters,
			})
		}
	}

	// User metadata
	if req.User != "" {
		ar.Metadata = &anthropicMetadata{UserID: req.User}
	}

	// Pass through thinking/extended reasoning config
	if req.Thinking != nil {
		ar.Thinking = &anthropicThinking{
			Type:         req.Thinking.Type,
			BudgetTokens: req.Thinking.BudgetTokens,
		}
	}

	return ar
}

func convertAnthropicResponse(resp *anthropicResponse, requestModel string) *ai.ChatCompletionResponse {
	model := resp.Model
	if model == "" {
		model = requestModel
	}

	choice := ai.Choice{
		Index: 0,
	}

	// Convert content blocks to message (skip thinking blocks for text output)
	var contentParts []string
	var toolCalls []ai.ToolCall
	for _, block := range resp.Content {
		switch block.Type {
		case "text":
			contentParts = append(contentParts, block.Text)
		case "thinking":
			// Thinking blocks are internal reasoning; not included in message content.
			// They are available in the raw response for consumers that need them.
		case "tool_use":
			toolCalls = append(toolCalls, ai.ToolCall{
				ID:   block.ID,
				Type: "function",
				Function: ai.ToolCallFunction{
					Name:      block.Name,
					Arguments: string(block.Input),
				},
			})
		}
	}

	content := strings.Join(contentParts, "")
	contentJSON, _ := json.Marshal(content)
	choice.Message = ai.Message{
		Role:      "assistant",
		Content:   contentJSON,
		ToolCalls: toolCalls,
	}

	// Map stop_reason to finish_reason
	finishReason := mapAnthropicStopReason(resp.StopReason)
	choice.FinishReason = &finishReason

	usage := &ai.Usage{
		PromptTokens:             resp.Usage.InputTokens,
		CompletionTokens:         resp.Usage.OutputTokens,
		TotalTokens:              resp.Usage.InputTokens + resp.Usage.OutputTokens,
		PromptTokensCached:       resp.Usage.CacheRead,
		CacheCreationInputTokens: resp.Usage.CacheCreation,
		CacheReadInputTokens:     resp.Usage.CacheRead,
	}
	if resp.Usage.CacheRead > 0 {
		usage.PromptTokensDetails = &ai.PromptTokensDetails{
			CachedTokens: resp.Usage.CacheRead,
		}
	}

	return &ai.ChatCompletionResponse{
		ID:      resp.ID,
		Object:  "chat.completion",
		Created: 0, // Anthropic doesn't return created timestamp
		Model:   model,
		Choices: []ai.Choice{choice},
		Usage:   usage,
	}
}

func mapAnthropicStopReason(reason string) string {
	switch reason {
	case "end_turn":
		return "stop"
	case "max_tokens":
		return "length"
	case "stop_sequence":
		return "stop"
	case "tool_use":
		return "tool_calls"
	default:
		return reason
	}
}

func extractAnthropicError(resp *http.Response) *ai.AIError {
	body, _ := io.ReadAll(resp.Body)

	var errResp struct {
		Type  string `json:"type"`
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error.Message != "" {
		return &ai.AIError{
			StatusCode: resp.StatusCode,
			Type:       errResp.Error.Type,
			Message:    errResp.Error.Message,
		}
	}

	return &ai.AIError{
		StatusCode: resp.StatusCode,
		Type:       "api_error",
		Message:    fmt.Sprintf("Anthropic API error: %s", string(body)),
	}
}

// Anthropic streaming event types
type anthropicMessageStart struct {
	Type    string            `json:"type"`
	Message anthropicResponse `json:"message"`
}

type anthropicContentBlockStart struct {
	Type         string                `json:"type"`
	Index        int                   `json:"index"`
	ContentBlock anthropicContentBlock `json:"content_block"`
}

type anthropicContentBlockDelta struct {
	Type  string                     `json:"type"`
	Index int                        `json:"index"`
	Delta anthropicContentBlockDeltaData `json:"delta"`
}

type anthropicContentBlockDeltaData struct {
	Type        string          `json:"type"`
	Text        string          `json:"text,omitempty"`
	PartialJSON string          `json:"partial_json,omitempty"`
}

type anthropicMessageDelta struct {
	Type  string `json:"type"`
	Delta struct {
		StopReason   string  `json:"stop_reason"`
		StopSequence *string `json:"stop_sequence"`
	} `json:"delta"`
	Usage anthropicUsage `json:"usage"`
}

// anthropicStreamReader converts Anthropic SSE events to OpenAI StreamChunks.
type anthropicStreamReader struct {
	parser     *ai.SSEParser
	body       io.ReadCloser
	model      string
	msgID      string
	blockTypes map[int]string // index -> content block type
}

// Read performs the read operation on the anthropicStreamReader.
func (r *anthropicStreamReader) Read() (*ai.StreamChunk, error) {
	if r.blockTypes == nil {
		r.blockTypes = make(map[int]string)
	}

	for {
		event, err := r.parser.ReadEvent()
		if err != nil {
			return nil, err
		}

		switch event.Event {
		case "message_start":
			var msg anthropicMessageStart
			if err := json.Unmarshal([]byte(event.Data), &msg); err != nil {
				ai.ReleaseSSEEvent(event)
				continue
			}
			r.msgID = msg.Message.ID
			r.model = msg.Message.Model
			ai.ReleaseSSEEvent(event)
			// Send initial chunk with role
			role := "assistant"
			return &ai.StreamChunk{
				ID:      r.msgID,
				Object:  "chat.completion.chunk",
				Model:   r.model,
				Choices: []ai.StreamChoice{{
					Index: 0,
					Delta: ai.StreamDelta{Role: role},
				}},
			}, nil

		case "content_block_start":
			var cbs anthropicContentBlockStart
			if err := json.Unmarshal([]byte(event.Data), &cbs); err != nil {
				ai.ReleaseSSEEvent(event)
				continue
			}
			r.blockTypes[cbs.Index] = cbs.ContentBlock.Type
			ai.ReleaseSSEEvent(event)
			if cbs.ContentBlock.Type == "tool_use" {
				// Send tool call start
				args := ""
				return &ai.StreamChunk{
					ID:     r.msgID,
					Object: "chat.completion.chunk",
					Model:  r.model,
					Choices: []ai.StreamChoice{{
						Index: 0,
						Delta: ai.StreamDelta{
							ToolCalls: []ai.ToolCallDelta{{
								Index: cbs.Index,
								ID:    cbs.ContentBlock.ID,
								Type:  "function",
								Function: &ai.ToolCallFunction{
									Name:      cbs.ContentBlock.Name,
									Arguments: args,
								},
							}},
						},
					}},
				}, nil
			}
			continue

		case "content_block_delta":
			var cbd anthropicContentBlockDelta
			if err := json.Unmarshal([]byte(event.Data), &cbd); err != nil {
				ai.ReleaseSSEEvent(event)
				continue
			}
			ai.ReleaseSSEEvent(event)

			blockType := r.blockTypes[cbd.Index]
			if blockType == "tool_use" {
				// Tool use argument delta
				return &ai.StreamChunk{
					ID:     r.msgID,
					Object: "chat.completion.chunk",
					Model:  r.model,
					Choices: []ai.StreamChoice{{
						Index: 0,
						Delta: ai.StreamDelta{
							ToolCalls: []ai.ToolCallDelta{{
								Index: cbd.Index,
								Function: &ai.ToolCallFunction{
									Arguments: cbd.Delta.PartialJSON,
								},
							}},
						},
					}},
				}, nil
			}

			// Text content delta
			text := cbd.Delta.Text
			return &ai.StreamChunk{
				ID:     r.msgID,
				Object: "chat.completion.chunk",
				Model:  r.model,
				Choices: []ai.StreamChoice{{
					Index: 0,
					Delta: ai.StreamDelta{Content: &text},
				}},
			}, nil

		case "content_block_stop":
			ai.ReleaseSSEEvent(event)
			continue

		case "message_delta":
			var md anthropicMessageDelta
			if err := json.Unmarshal([]byte(event.Data), &md); err != nil {
				ai.ReleaseSSEEvent(event)
				continue
			}
			ai.ReleaseSSEEvent(event)
			finishReason := mapAnthropicStopReason(md.Delta.StopReason)
			return &ai.StreamChunk{
				ID:     r.msgID,
				Object: "chat.completion.chunk",
				Model:  r.model,
				Choices: []ai.StreamChoice{{
					Index:        0,
					Delta:        ai.StreamDelta{},
					FinishReason: &finishReason,
				}},
				Usage: &ai.Usage{
					CompletionTokens: md.Usage.OutputTokens,
				},
			}, nil

		case "message_stop":
			ai.ReleaseSSEEvent(event)
			return nil, io.EOF

		case "ping":
			ai.ReleaseSSEEvent(event)
			continue

		case "error":
			errMsg := event.Data
			ai.ReleaseSSEEvent(event)
			return nil, fmt.Errorf("anthropic stream error: %s", errMsg)

		default:
			ai.ReleaseSSEEvent(event)
			continue
		}
	}
}

// Close releases resources held by the anthropicStreamReader.
func (r *anthropicStreamReader) Close() error {
	r.parser.Close()
	return r.body.Close()
}
