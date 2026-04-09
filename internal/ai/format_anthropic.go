// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	json "github.com/goccy/go-json"
)

// Anthropic Messages API request types.

// AnthropicRequest represents an Anthropic Messages API request.
type AnthropicRequest struct {
	Model         string             `json:"model"`
	Messages      []AnthropicMessage `json:"messages"`
	System        json.RawMessage    `json:"system,omitempty"`
	MaxTokens     int                `json:"max_tokens"`
	Temperature   *float64           `json:"temperature,omitempty"`
	TopP          *float64           `json:"top_p,omitempty"`
	TopK          *int               `json:"top_k,omitempty"`
	Stream        bool               `json:"stream,omitempty"`
	StopSequences []string           `json:"stop_sequences,omitempty"`
	Metadata      *AnthropicMetadata `json:"metadata,omitempty"`
	Tools         []AnthropicTool    `json:"tools,omitempty"`
	ToolChoice    json.RawMessage    `json:"tool_choice,omitempty"`
}

// AnthropicMessage represents a message in the Anthropic format.
type AnthropicMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"` // string or []AnthropicContentBlock
}

// AnthropicContentBlock represents a content block in an Anthropic message.
type AnthropicContentBlock struct {
	Type string `json:"type"` // "text", "image", "tool_use", "tool_result"

	// text block fields
	Text string `json:"text,omitempty"`

	// image block fields
	Source *AnthropicImageSource `json:"source,omitempty"`

	// tool_use block fields
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`

	// tool_result block fields
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   json.RawMessage `json:"content,omitempty"` // string or []AnthropicContentBlock
	IsError   *bool           `json:"is_error,omitempty"`
}

// AnthropicImageSource represents the source for an image content block.
type AnthropicImageSource struct {
	Type      string `json:"type"`       // "base64"
	MediaType string `json:"media_type"` // e.g. "image/png"
	Data      string `json:"data"`
}

// AnthropicMetadata holds optional metadata for an Anthropic request.
type AnthropicMetadata struct {
	UserID string `json:"user_id,omitempty"`
}

// AnthropicTool represents a tool definition in Anthropic format.
type AnthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
}

// Anthropic Messages API response types.

// AnthropicResponse represents an Anthropic Messages API response.
type AnthropicResponse struct {
	ID           string                  `json:"id"`
	Type         string                  `json:"type"`
	Role         string                  `json:"role"`
	Content      []AnthropicContentBlock `json:"content"`
	Model        string                  `json:"model"`
	StopReason   *string                 `json:"stop_reason"`
	StopSequence *string                 `json:"stop_sequence,omitempty"`
	Usage        AnthropicUsage          `json:"usage"`
}

// AnthropicUsage represents token usage in Anthropic format.
type AnthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// Anthropic SSE streaming event types.

// AnthropicStreamEvent represents an Anthropic SSE event for streaming responses.
type AnthropicStreamEvent struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"-"` // raw JSON payload for the SSE data field
}

// anthropicMessageStart is the payload for message_start events.
type anthropicMessageStart struct {
	Type    string            `json:"type"`
	Message AnthropicResponse `json:"message"`
}

// anthropicContentBlockStart is the payload for content_block_start events.
type anthropicContentBlockStart struct {
	Type         string                `json:"type"`
	Index        int                   `json:"index"`
	ContentBlock AnthropicContentBlock `json:"content_block"`
}

// anthropicContentBlockDelta is the payload for content_block_delta events.
type anthropicContentBlockDelta struct {
	Type  string                     `json:"type"`
	Index int                        `json:"index"`
	Delta anthropicContentBlockInner `json:"delta"`
}

type anthropicContentBlockInner struct {
	Type string `json:"type"` // "text_delta", "input_json_delta"
	Text string `json:"text,omitempty"`
}

// anthropicContentBlockStop is the payload for content_block_stop events.
type anthropicContentBlockStop struct {
	Type  string `json:"type"`
	Index int    `json:"index"`
}

// anthropicMessageDelta is the payload for message_delta events.
type anthropicMessageDelta struct {
	Type  string                     `json:"type"`
	Delta anthropicMessageDeltaInner `json:"delta"`
	Usage *AnthropicUsage            `json:"usage,omitempty"`
}

type anthropicMessageDeltaInner struct {
	StopReason   *string `json:"stop_reason"`
	StopSequence *string `json:"stop_sequence,omitempty"`
}

// anthropicMessageStop is the payload for message_stop events.
type anthropicMessageStop struct {
	Type string `json:"type"`
}

// anthropicPing is the payload for ping events.
type anthropicPing struct {
	Type string `json:"type"`
}

// AnthropicToOpenAI converts an Anthropic Messages API request to OpenAI chat completion format.
func AnthropicToOpenAI(req *AnthropicRequest) (*ChatCompletionRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("nil anthropic request")
	}

	result := &ChatCompletionRequest{
		Model:       req.Model,
		Temperature: req.Temperature,
		TopP:        req.TopP,
	}

	// max_tokens is required in Anthropic
	if req.MaxTokens > 0 {
		result.MaxTokens = &req.MaxTokens
	}

	// Stream
	if req.Stream {
		streamTrue := true
		result.Stream = &streamTrue
	}

	// Stop sequences
	if len(req.StopSequences) > 0 {
		raw, err := json.Marshal(req.StopSequences)
		if err != nil {
			return nil, fmt.Errorf("marshal stop_sequences: %w", err)
		}
		result.Stop = raw
	}

	// System message - can be string or array of content blocks
	if len(req.System) > 0 {
		systemMsg, err := parseAnthropicSystem(req.System)
		if err != nil {
			return nil, fmt.Errorf("parse system: %w", err)
		}
		if systemMsg != nil {
			result.Messages = append(result.Messages, *systemMsg)
		}
	}

	// Convert messages
	for i, msg := range req.Messages {
		converted, err := convertAnthropicMessage(msg)
		if err != nil {
			return nil, fmt.Errorf("message[%d]: %w", i, err)
		}
		result.Messages = append(result.Messages, converted...)
	}

	// Convert tools
	if len(req.Tools) > 0 {
		for _, tool := range req.Tools {
			result.Tools = append(result.Tools, Tool{
				Type: "function",
				Function: ToolFunction{
					Name:        tool.Name,
					Description: tool.Description,
					Parameters:  tool.InputSchema,
				},
			})
		}
	}

	// Convert tool_choice
	if len(req.ToolChoice) > 0 {
		converted, err := convertAnthropicToolChoice(req.ToolChoice)
		if err != nil {
			return nil, fmt.Errorf("tool_choice: %w", err)
		}
		result.ToolChoice = converted
	}

	// Metadata user_id maps to user field
	if req.Metadata != nil && req.Metadata.UserID != "" {
		result.User = req.Metadata.UserID
	}

	return result, nil
}

// parseAnthropicSystem parses the system field which can be a string or array of content blocks.
func parseAnthropicSystem(raw json.RawMessage) (*Message, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	// Try string first
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s == "" {
			return nil, nil
		}
		return &Message{
			Role:    "system",
			Content: json.RawMessage(strconv.Quote(s)),
		}, nil
	}

	// Try array of content blocks
	var blocks []AnthropicContentBlock
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return nil, fmt.Errorf("system must be string or array of content blocks: %w", err)
	}

	var b strings.Builder
	for _, block := range blocks {
		if block.Type == "text" {
			b.WriteString(block.Text)
		}
	}
	text := b.String()
	if text == "" {
		return nil, nil
	}
	return &Message{
		Role:    "system",
		Content: json.RawMessage(strconv.Quote(text)),
	}, nil
}

// convertAnthropicMessage converts an Anthropic message to one or more OpenAI messages.
func convertAnthropicMessage(msg AnthropicMessage) ([]Message, error) {
	if len(msg.Content) == 0 {
		return nil, nil
	}

	// Try as a string first
	var s string
	if err := json.Unmarshal(msg.Content, &s); err == nil {
		return []Message{{
			Role:    msg.Role,
			Content: json.RawMessage(strconv.Quote(s)),
		}}, nil
	}

	// Parse as array of content blocks
	var blocks []AnthropicContentBlock
	if err := json.Unmarshal(msg.Content, &blocks); err != nil {
		return nil, fmt.Errorf("content must be string or array of content blocks: %w", err)
	}

	// Check for tool_use blocks (assistant messages with tool calls)
	if msg.Role == "assistant" {
		return convertAssistantBlocks(blocks)
	}

	// Check for tool_result blocks (user messages with tool results)
	hasToolResult := false
	for _, b := range blocks {
		if b.Type == "tool_result" {
			hasToolResult = true
			break
		}
	}
	if hasToolResult {
		return convertToolResultBlocks(blocks)
	}

	// Convert regular content blocks to OpenAI content parts
	parts, err := convertContentBlocksToParts(blocks)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(parts)
	if err != nil {
		return nil, fmt.Errorf("marshal content parts: %w", err)
	}

	return []Message{{
		Role:    msg.Role,
		Content: raw,
	}}, nil
}

// convertAssistantBlocks converts Anthropic assistant blocks which may contain text and tool_use.
func convertAssistantBlocks(blocks []AnthropicContentBlock) ([]Message, error) {
	var textParts strings.Builder
	var toolCalls []ToolCall

	for _, b := range blocks {
		switch b.Type {
		case "text":
			textParts.WriteString(b.Text)
		case "tool_use":
			args := "{}"
			if len(b.Input) > 0 {
				args = string(b.Input)
			}
			toolCalls = append(toolCalls, ToolCall{
				ID:   b.ID,
				Type: "function",
				Function: ToolCallFunction{
					Name:      b.Name,
					Arguments: args,
				},
			})
		}
	}

	msg := Message{
		Role:      "assistant",
		ToolCalls: toolCalls,
	}
	text := textParts.String()
	if text != "" {
		msg.Content = json.RawMessage(strconv.Quote(text))
	} else {
		msg.Content = json.RawMessage("null")
	}

	return []Message{msg}, nil
}

// convertToolResultBlocks converts Anthropic tool_result blocks to OpenAI tool messages.
func convertToolResultBlocks(blocks []AnthropicContentBlock) ([]Message, error) {
	var msgs []Message
	for _, b := range blocks {
		if b.Type == "tool_result" {
			content := extractToolResultContent(b)
			msgs = append(msgs, Message{
				Role:       "tool",
				ToolCallID: b.ToolUseID,
				Content:    json.RawMessage(strconv.Quote(content)),
			})
		}
	}
	return msgs, nil
}

// extractToolResultContent extracts text from a tool_result content field.
func extractToolResultContent(b AnthropicContentBlock) string {
	if len(b.Content) == 0 {
		return ""
	}

	// Try as string
	var s string
	if err := json.Unmarshal(b.Content, &s); err == nil {
		return s
	}

	// Try as array of content blocks
	var inner []AnthropicContentBlock
	if err := json.Unmarshal(b.Content, &inner); err == nil {
		var sb strings.Builder
		for _, ib := range inner {
			if ib.Type == "text" {
				sb.WriteString(ib.Text)
			}
		}
		return sb.String()
	}

	return string(b.Content)
}

// convertContentBlocksToParts converts Anthropic content blocks to OpenAI content parts.
func convertContentBlocksToParts(blocks []AnthropicContentBlock) ([]ContentPart, error) {
	var parts []ContentPart
	for _, b := range blocks {
		switch b.Type {
		case "text":
			parts = append(parts, ContentPart{
				Type: "text",
				Text: b.Text,
			})
		case "image":
			if b.Source == nil {
				continue
			}
			// Convert base64 image to OpenAI image_url format
			dataURI := fmt.Sprintf("data:%s;base64,%s", b.Source.MediaType, b.Source.Data)
			parts = append(parts, ContentPart{
				Type:     "image_url",
				ImageURL: &ImageURL{URL: dataURI},
			})
		default:
			// Pass through unknown types as text if they have text
			if b.Text != "" {
				parts = append(parts, ContentPart{
					Type: "text",
					Text: b.Text,
				})
			}
		}
	}
	return parts, nil
}

// convertAnthropicToolChoice converts Anthropic tool_choice to OpenAI format.
func convertAnthropicToolChoice(raw json.RawMessage) (json.RawMessage, error) {
	// Anthropic tool_choice can be:
	// {"type": "auto"} -> "auto"
	// {"type": "any"} -> "required"
	// {"type": "tool", "name": "..."} -> {"type": "function", "function": {"name": "..."}}
	var tc struct {
		Type string `json:"type"`
		Name string `json:"name,omitempty"`
	}
	if err := json.Unmarshal(raw, &tc); err != nil {
		// Might be a string already, pass through
		return raw, nil
	}

	switch tc.Type {
	case "auto":
		return json.RawMessage(`"auto"`), nil
	case "any":
		return json.RawMessage(`"required"`), nil
	case "tool":
		openAIChoice := map[string]interface{}{
			"type": "function",
			"function": map[string]string{
				"name": tc.Name,
			},
		}
		data, err := json.Marshal(openAIChoice)
		if err != nil {
			return nil, err
		}
		return data, nil
	default:
		return raw, nil
	}
}

// OpenAIToAnthropic converts an OpenAI chat completion response to Anthropic Messages API format.
func OpenAIToAnthropic(resp *ChatCompletionResponse) (*AnthropicResponse, error) {
	if resp == nil {
		return nil, fmt.Errorf("nil openai response")
	}

	result := &AnthropicResponse{
		ID:    convertIDPrefix(resp.ID),
		Type:  "message",
		Role:  "assistant",
		Model: resp.Model,
	}

	// Convert usage
	if resp.Usage != nil {
		result.Usage = AnthropicUsage{
			InputTokens:  resp.Usage.PromptTokens,
			OutputTokens: resp.Usage.CompletionTokens,
		}
	}

	// Convert choices - take the first choice
	if len(resp.Choices) > 0 {
		choice := resp.Choices[0]

		// Convert finish_reason to stop_reason
		if choice.FinishReason != nil {
			stopReason := convertFinishReason(*choice.FinishReason)
			result.StopReason = &stopReason
		}

		// Convert message content
		content := choice.Message.ContentString()
		if content != "" {
			result.Content = append(result.Content, AnthropicContentBlock{
				Type: "text",
				Text: content,
			})
		}

		// Convert tool calls to tool_use content blocks
		for _, tc := range choice.Message.ToolCalls {
			block := AnthropicContentBlock{
				Type: "tool_use",
				ID:   tc.ID,
				Name: tc.Function.Name,
			}
			if tc.Function.Arguments != "" {
				block.Input = json.RawMessage(tc.Function.Arguments)
			} else {
				block.Input = json.RawMessage("{}")
			}
			result.Content = append(result.Content, block)
		}
	}

	// Ensure content is never nil
	if result.Content == nil {
		result.Content = []AnthropicContentBlock{}
	}

	return result, nil
}

// convertFinishReason maps OpenAI finish_reason to Anthropic stop_reason.
func convertFinishReason(reason string) string {
	switch reason {
	case "stop":
		return "end_turn"
	case "length":
		return "max_tokens"
	case "tool_calls":
		return "tool_use"
	case "content_filter":
		return "end_turn"
	default:
		return "end_turn"
	}
}

// convertIDPrefix converts an OpenAI response ID to Anthropic format.
func convertIDPrefix(id string) string {
	if strings.HasPrefix(id, "chatcmpl-") {
		return "msg_" + strings.TrimPrefix(id, "chatcmpl-")
	}
	if strings.HasPrefix(id, "msg_") {
		return id
	}
	return "msg_" + id
}

// OpenAIStreamToAnthropic converts an OpenAI streaming chunk to Anthropic SSE events.
// isFirst indicates whether this is the first chunk in the stream.
// contentBlockStarted tracks whether a content_block_start has been emitted.
// Returns the events and updated contentBlockStarted state.
func OpenAIStreamToAnthropic(chunk *StreamChunk, isFirst bool, contentBlockStarted bool) ([]AnthropicStreamEvent, bool) {
	if chunk == nil {
		return nil, contentBlockStarted
	}

	var events []AnthropicStreamEvent

	// First chunk: emit message_start with ping
	if isFirst {
		msgStart := anthropicMessageStart{
			Type: "message_start",
			Message: AnthropicResponse{
				ID:      convertIDPrefix(chunk.ID),
				Type:    "message",
				Role:    "assistant",
				Content: []AnthropicContentBlock{},
				Model:   chunk.Model,
				Usage: AnthropicUsage{
					InputTokens:  0,
					OutputTokens: 0,
				},
			},
		}
		data, _ := json.Marshal(msgStart)
		events = append(events, AnthropicStreamEvent{
			Type: "message_start",
			Data: data,
		})

		// Ping
		pingData, _ := json.Marshal(anthropicPing{Type: "ping"})
		events = append(events, AnthropicStreamEvent{
			Type: "ping",
			Data: pingData,
		})
	}

	// Process choices
	for _, choice := range chunk.Choices {
		// Check for content delta
		if choice.Delta.Content != nil && *choice.Delta.Content != "" {
			// Start content block if not started
			if !contentBlockStarted {
				blockStart := anthropicContentBlockStart{
					Type:  "content_block_start",
					Index: 0,
					ContentBlock: AnthropicContentBlock{
						Type: "text",
						Text: "",
					},
				}
				data, _ := json.Marshal(blockStart)
				events = append(events, AnthropicStreamEvent{
					Type: "content_block_start",
					Data: data,
				})
				contentBlockStarted = true
			}

			// Content delta
			delta := anthropicContentBlockDelta{
				Type:  "content_block_delta",
				Index: 0,
				Delta: anthropicContentBlockInner{
					Type: "text_delta",
					Text: *choice.Delta.Content,
				},
			}
			data, _ := json.Marshal(delta)
			events = append(events, AnthropicStreamEvent{
				Type: "content_block_delta",
				Data: data,
			})
		}

		// Check for tool call deltas
		for _, tc := range choice.Delta.ToolCalls {
			if tc.ID != "" {
				// New tool call - start a new content block
				blockStart := anthropicContentBlockStart{
					Type:  "content_block_start",
					Index: tc.Index,
					ContentBlock: AnthropicContentBlock{
						Type:  "tool_use",
						ID:    tc.ID,
						Name:  tc.Function.Name,
						Input: json.RawMessage("{}"),
					},
				}
				data, _ := json.Marshal(blockStart)
				events = append(events, AnthropicStreamEvent{
					Type: "content_block_start",
					Data: data,
				})
			}
			if tc.Function != nil && tc.Function.Arguments != "" {
				delta := anthropicContentBlockDelta{
					Type:  "content_block_delta",
					Index: tc.Index,
					Delta: anthropicContentBlockInner{
						Type: "input_json_delta",
						Text: tc.Function.Arguments,
					},
				}
				data, _ := json.Marshal(delta)
				events = append(events, AnthropicStreamEvent{
					Type: "content_block_delta",
					Data: data,
				})
			}
		}

		// Check for finish_reason (final chunk)
		if choice.FinishReason != nil {
			// Close content block if one was started
			if contentBlockStarted {
				blockStop := anthropicContentBlockStop{
					Type:  "content_block_stop",
					Index: 0,
				}
				data, _ := json.Marshal(blockStop)
				events = append(events, AnthropicStreamEvent{
					Type: "content_block_stop",
					Data: data,
				})
			}

			// Message delta with stop reason
			stopReason := convertFinishReason(*choice.FinishReason)
			var outputTokens int
			if chunk.Usage != nil {
				outputTokens = chunk.Usage.CompletionTokens
			}
			msgDelta := anthropicMessageDelta{
				Type: "message_delta",
				Delta: anthropicMessageDeltaInner{
					StopReason: &stopReason,
				},
				Usage: &AnthropicUsage{
					OutputTokens: outputTokens,
				},
			}
			data, _ := json.Marshal(msgDelta)
			events = append(events, AnthropicStreamEvent{
				Type: "message_delta",
				Data: data,
			})

			// Message stop
			msgStop := anthropicMessageStop{Type: "message_stop"}
			stopData, _ := json.Marshal(msgStop)
			events = append(events, AnthropicStreamEvent{
				Type: "message_stop",
				Data: stopData,
			})
		}
	}

	return events, contentBlockStarted
}

// WriteAnthropicSSEEvent writes an Anthropic SSE event to the writer.
func WriteAnthropicSSEEvent(sw *SSEWriter, evt AnthropicStreamEvent) error {
	sseEvt := sseEventPool.Get().(*SSEEvent)
	sseEvt.Event = evt.Type
	sseEvt.Data = string(evt.Data)
	sseEvt.ID = ""
	err := sw.WriteEvent(sseEvt)
	ReleaseSSEEvent(sseEvt)
	return err
}

// AnthropicErrorToResponse converts an AIError to an Anthropic error format.
func AnthropicErrorToResponse(err *AIError) map[string]interface{} {
	errType := "api_error"
	switch {
	case err.StatusCode == 400:
		errType = "invalid_request_error"
	case err.StatusCode == 401:
		errType = "authentication_error"
	case err.StatusCode == 403:
		errType = "permission_error"
	case err.StatusCode == 404:
		errType = "not_found_error"
	case err.StatusCode == 429:
		errType = "rate_limit_error"
	case err.StatusCode >= 500:
		errType = "api_error"
	}

	return map[string]interface{}{
		"type": "error",
		"error": map[string]interface{}{
			"type":    errType,
			"message": err.Message,
		},
	}
}

// WriteAnthropicError writes an error response in Anthropic format.
func WriteAnthropicError(w http.ResponseWriter, err *AIError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.StatusCode)
	_ = json.NewEncoder(w).Encode(AnthropicErrorToResponse(err))
}

