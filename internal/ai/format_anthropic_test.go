package ai

import (
	"testing"

	json "github.com/goccy/go-json"
)

func TestAnthropicToOpenAI_SimpleText(t *testing.T) {
	req := &AnthropicRequest{
		Model:     "claude-3-opus-20240229",
		MaxTokens: 1024,
		Messages: []AnthropicMessage{
			{
				Role:    "user",
				Content: json.RawMessage(`"Hello, how are you?"`),
			},
		},
	}

	result, err := AnthropicToOpenAI(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Model != "claude-3-opus-20240229" {
		t.Errorf("model = %q, want %q", result.Model, "claude-3-opus-20240229")
	}
	if result.MaxTokens == nil || *result.MaxTokens != 1024 {
		t.Errorf("max_tokens = %v, want 1024", result.MaxTokens)
	}
	if len(result.Messages) != 1 {
		t.Fatalf("messages len = %d, want 1", len(result.Messages))
	}
	if result.Messages[0].Role != "user" {
		t.Errorf("role = %q, want %q", result.Messages[0].Role, "user")
	}
	if result.Messages[0].ContentString() != "Hello, how are you?" {
		t.Errorf("content = %q, want %q", result.Messages[0].ContentString(), "Hello, how are you?")
	}
}

func TestAnthropicToOpenAI_SystemMessage(t *testing.T) {
	tests := []struct {
		name       string
		system     json.RawMessage
		wantSystem string
	}{
		{
			name:       "string system",
			system:     json.RawMessage(`"You are a helpful assistant."`),
			wantSystem: "You are a helpful assistant.",
		},
		{
			name:       "array system",
			system:     json.RawMessage(`[{"type": "text", "text": "You are a helpful assistant."}]`),
			wantSystem: "You are a helpful assistant.",
		},
		{
			name:       "multi-block array system",
			system:     json.RawMessage(`[{"type": "text", "text": "Rule 1. "}, {"type": "text", "text": "Rule 2."}]`),
			wantSystem: "Rule 1. Rule 2.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &AnthropicRequest{
				Model:     "claude-3-opus-20240229",
				MaxTokens: 100,
				System:    tt.system,
				Messages: []AnthropicMessage{
					{
						Role:    "user",
						Content: json.RawMessage(`"Hello"`),
					},
				},
			}

			result, err := AnthropicToOpenAI(req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(result.Messages) < 2 {
				t.Fatalf("expected at least 2 messages (system + user), got %d", len(result.Messages))
			}
			if result.Messages[0].Role != "system" {
				t.Errorf("first message role = %q, want %q", result.Messages[0].Role, "system")
			}
			if result.Messages[0].ContentString() != tt.wantSystem {
				t.Errorf("system content = %q, want %q", result.Messages[0].ContentString(), tt.wantSystem)
			}
		})
	}
}

func TestAnthropicToOpenAI_MultipleMessages(t *testing.T) {
	req := &AnthropicRequest{
		Model:     "claude-3-sonnet-20240229",
		MaxTokens: 256,
		Messages: []AnthropicMessage{
			{
				Role:    "user",
				Content: json.RawMessage(`"First message"`),
			},
			{
				Role:    "assistant",
				Content: json.RawMessage(`"I understand."`),
			},
			{
				Role:    "user",
				Content: json.RawMessage(`"Second message"`),
			},
		},
	}

	result, err := AnthropicToOpenAI(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Messages) != 3 {
		t.Fatalf("messages len = %d, want 3", len(result.Messages))
	}
	if result.Messages[0].ContentString() != "First message" {
		t.Errorf("msg[0] content = %q, want %q", result.Messages[0].ContentString(), "First message")
	}
	if result.Messages[1].Role != "assistant" {
		t.Errorf("msg[1] role = %q, want %q", result.Messages[1].Role, "assistant")
	}
}

func TestAnthropicToOpenAI_WithTools(t *testing.T) {
	req := &AnthropicRequest{
		Model:     "claude-3-opus-20240229",
		MaxTokens: 1024,
		Messages: []AnthropicMessage{
			{Role: "user", Content: json.RawMessage(`"What is the weather?"`)},
		},
		Tools: []AnthropicTool{
			{
				Name:        "get_weather",
				Description: "Get the current weather",
				InputSchema: json.RawMessage(`{"type": "object", "properties": {"location": {"type": "string"}}}`),
			},
		},
	}

	result, err := AnthropicToOpenAI(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Tools) != 1 {
		t.Fatalf("tools len = %d, want 1", len(result.Tools))
	}
	if result.Tools[0].Type != "function" {
		t.Errorf("tool type = %q, want %q", result.Tools[0].Type, "function")
	}
	if result.Tools[0].Function.Name != "get_weather" {
		t.Errorf("tool name = %q, want %q", result.Tools[0].Function.Name, "get_weather")
	}
	if result.Tools[0].Function.Description != "Get the current weather" {
		t.Errorf("tool description = %q, want %q", result.Tools[0].Function.Description, "Get the current weather")
	}
}

func TestAnthropicToOpenAI_ToolResult(t *testing.T) {
	req := &AnthropicRequest{
		Model:     "claude-3-opus-20240229",
		MaxTokens: 1024,
		Messages: []AnthropicMessage{
			{Role: "user", Content: json.RawMessage(`"What is the weather?"`)},
			{
				Role: "assistant",
				Content: json.RawMessage(`[
					{"type": "text", "text": "Let me check."},
					{"type": "tool_use", "id": "call_123", "name": "get_weather", "input": {"location": "NYC"}}
				]`),
			},
			{
				Role: "user",
				Content: json.RawMessage(`[
					{"type": "tool_result", "tool_use_id": "call_123", "content": "72°F and sunny"}
				]`),
			},
		},
	}

	result, err := AnthropicToOpenAI(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have: user message, assistant message with tool call, tool result message
	if len(result.Messages) < 3 {
		t.Fatalf("messages len = %d, want >= 3", len(result.Messages))
	}

	// Check assistant message has tool calls
	assistantMsg := result.Messages[1]
	if len(assistantMsg.ToolCalls) != 1 {
		t.Fatalf("tool_calls len = %d, want 1", len(assistantMsg.ToolCalls))
	}
	if assistantMsg.ToolCalls[0].ID != "call_123" {
		t.Errorf("tool call id = %q, want %q", assistantMsg.ToolCalls[0].ID, "call_123")
	}
	if assistantMsg.ToolCalls[0].Function.Name != "get_weather" {
		t.Errorf("tool call name = %q, want %q", assistantMsg.ToolCalls[0].Function.Name, "get_weather")
	}

	// Check tool result message
	toolMsg := result.Messages[2]
	if toolMsg.Role != "tool" {
		t.Errorf("tool msg role = %q, want %q", toolMsg.Role, "tool")
	}
	if toolMsg.ToolCallID != "call_123" {
		t.Errorf("tool_call_id = %q, want %q", toolMsg.ToolCallID, "call_123")
	}
}

func TestAnthropicToOpenAI_ImageContent(t *testing.T) {
	req := &AnthropicRequest{
		Model:     "claude-3-opus-20240229",
		MaxTokens: 1024,
		Messages: []AnthropicMessage{
			{
				Role: "user",
				Content: json.RawMessage(`[
					{"type": "text", "text": "What is in this image?"},
					{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBOR..."}}
				]`),
			},
		},
	}

	result, err := AnthropicToOpenAI(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Messages) != 1 {
		t.Fatalf("messages len = %d, want 1", len(result.Messages))
	}

	// Parse the content as array of parts
	var parts []ContentPart
	if err := json.Unmarshal(result.Messages[0].Content, &parts); err != nil {
		t.Fatalf("failed to unmarshal content: %v", err)
	}

	if len(parts) != 2 {
		t.Fatalf("content parts len = %d, want 2", len(parts))
	}
	if parts[0].Type != "text" {
		t.Errorf("part[0] type = %q, want %q", parts[0].Type, "text")
	}
	if parts[1].Type != "image_url" {
		t.Errorf("part[1] type = %q, want %q", parts[1].Type, "image_url")
	}
	if parts[1].ImageURL == nil {
		t.Fatal("part[1] image_url is nil")
	}
	if parts[1].ImageURL.URL != "data:image/png;base64,iVBOR..." {
		t.Errorf("part[1] url = %q, want data URI", parts[1].ImageURL.URL)
	}
}

func TestAnthropicToOpenAI_StopSequences(t *testing.T) {
	req := &AnthropicRequest{
		Model:         "claude-3-opus-20240229",
		MaxTokens:     1024,
		StopSequences: []string{"STOP", "END"},
		Messages: []AnthropicMessage{
			{Role: "user", Content: json.RawMessage(`"Hello"`)},
		},
	}

	result, err := AnthropicToOpenAI(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Stop) == 0 {
		t.Fatal("stop is empty, expected stop sequences")
	}

	var stops []string
	if err := json.Unmarshal(result.Stop, &stops); err != nil {
		t.Fatalf("failed to unmarshal stop: %v", err)
	}
	if len(stops) != 2 {
		t.Fatalf("stop len = %d, want 2", len(stops))
	}
	if stops[0] != "STOP" || stops[1] != "END" {
		t.Errorf("stops = %v, want [STOP, END]", stops)
	}
}

func TestAnthropicToOpenAI_Temperature(t *testing.T) {
	temp := 0.7
	topP := 0.9
	req := &AnthropicRequest{
		Model:       "claude-3-opus-20240229",
		MaxTokens:   1024,
		Temperature: &temp,
		TopP:        &topP,
		Messages: []AnthropicMessage{
			{Role: "user", Content: json.RawMessage(`"Hello"`)},
		},
	}

	result, err := AnthropicToOpenAI(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Temperature == nil || *result.Temperature != 0.7 {
		t.Errorf("temperature = %v, want 0.7", result.Temperature)
	}
	if result.TopP == nil || *result.TopP != 0.9 {
		t.Errorf("top_p = %v, want 0.9", result.TopP)
	}
}

func TestOpenAIToAnthropic_SimpleResponse(t *testing.T) {
	finishReason := "stop"
	resp := &ChatCompletionResponse{
		ID:      "chatcmpl-abc123",
		Object:  "chat.completion",
		Created: 1234567890,
		Model:   "gpt-4o",
		Choices: []Choice{
			{
				Index: 0,
				Message: Message{
					Role:    "assistant",
					Content: json.RawMessage(`"Hello! How can I help you?"`),
				},
				FinishReason: &finishReason,
			},
		},
		Usage: &Usage{
			PromptTokens:     10,
			CompletionTokens: 8,
			TotalTokens:      18,
		},
	}

	result, err := OpenAIToAnthropic(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Type != "message" {
		t.Errorf("type = %q, want %q", result.Type, "message")
	}
	if result.Role != "assistant" {
		t.Errorf("role = %q, want %q", result.Role, "assistant")
	}
	if result.ID != "msg_abc123" {
		t.Errorf("id = %q, want %q", result.ID, "msg_abc123")
	}
	if result.Model != "gpt-4o" {
		t.Errorf("model = %q, want %q", result.Model, "gpt-4o")
	}
	if len(result.Content) != 1 {
		t.Fatalf("content len = %d, want 1", len(result.Content))
	}
	if result.Content[0].Type != "text" {
		t.Errorf("content[0].type = %q, want %q", result.Content[0].Type, "text")
	}
	if result.Content[0].Text != "Hello! How can I help you?" {
		t.Errorf("content[0].text = %q, want %q", result.Content[0].Text, "Hello! How can I help you?")
	}
	if result.StopReason == nil || *result.StopReason != "end_turn" {
		t.Errorf("stop_reason = %v, want end_turn", result.StopReason)
	}
	if result.Usage.InputTokens != 10 {
		t.Errorf("input_tokens = %d, want 10", result.Usage.InputTokens)
	}
	if result.Usage.OutputTokens != 8 {
		t.Errorf("output_tokens = %d, want 8", result.Usage.OutputTokens)
	}
}

func TestOpenAIToAnthropic_ToolCallResponse(t *testing.T) {
	finishReason := "tool_calls"
	resp := &ChatCompletionResponse{
		ID:      "chatcmpl-tool-123",
		Object:  "chat.completion",
		Created: 1234567890,
		Model:   "gpt-4o",
		Choices: []Choice{
			{
				Index: 0,
				Message: Message{
					Role:    "assistant",
					Content: json.RawMessage("null"),
					ToolCalls: []ToolCall{
						{
							ID:   "call_abc",
							Type: "function",
							Function: ToolCallFunction{
								Name:      "get_weather",
								Arguments: `{"location":"NYC"}`,
							},
						},
					},
				},
				FinishReason: &finishReason,
			},
		},
		Usage: &Usage{
			PromptTokens:     15,
			CompletionTokens: 20,
			TotalTokens:      35,
		},
	}

	result, err := OpenAIToAnthropic(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.StopReason == nil || *result.StopReason != "tool_use" {
		t.Errorf("stop_reason = %v, want tool_use", result.StopReason)
	}

	// Should have tool_use content blocks
	if len(result.Content) < 1 {
		t.Fatalf("content len = %d, want >= 1", len(result.Content))
	}

	// Find the tool_use block
	found := false
	for _, block := range result.Content {
		if block.Type == "tool_use" {
			found = true
			if block.ID != "call_abc" {
				t.Errorf("tool_use id = %q, want %q", block.ID, "call_abc")
			}
			if block.Name != "get_weather" {
				t.Errorf("tool_use name = %q, want %q", block.Name, "get_weather")
			}
			var input map[string]string
			if err := json.Unmarshal(block.Input, &input); err != nil {
				t.Fatalf("failed to unmarshal tool input: %v", err)
			}
			if input["location"] != "NYC" {
				t.Errorf("tool input location = %q, want %q", input["location"], "NYC")
			}
		}
	}
	if !found {
		t.Error("no tool_use content block found")
	}
}

func TestOpenAIToAnthropic_StopReasons(t *testing.T) {
	tests := []struct {
		finishReason string
		wantStop     string
	}{
		{"stop", "end_turn"},
		{"length", "max_tokens"},
		{"tool_calls", "tool_use"},
		{"content_filter", "end_turn"},
		{"unknown_reason", "end_turn"},
	}

	for _, tt := range tests {
		t.Run(tt.finishReason, func(t *testing.T) {
			resp := &ChatCompletionResponse{
				ID:    "chatcmpl-test",
				Model: "gpt-4o",
				Choices: []Choice{
					{
						Message:      Message{Role: "assistant", Content: json.RawMessage(`"test"`)},
						FinishReason: &tt.finishReason,
					},
				},
				Usage: &Usage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2},
			}

			result, err := OpenAIToAnthropic(resp)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.StopReason == nil {
				t.Fatal("stop_reason is nil")
			}
			if *result.StopReason != tt.wantStop {
				t.Errorf("stop_reason = %q, want %q", *result.StopReason, tt.wantStop)
			}
		})
	}
}

func TestOpenAIToAnthropic_UsageMapping(t *testing.T) {
	resp := &ChatCompletionResponse{
		ID:    "chatcmpl-test",
		Model: "gpt-4o",
		Choices: []Choice{
			{
				Message: Message{Role: "assistant", Content: json.RawMessage(`"test"`)},
			},
		},
		Usage: &Usage{
			PromptTokens:     42,
			CompletionTokens: 58,
			TotalTokens:      100,
		},
	}

	result, err := OpenAIToAnthropic(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Usage.InputTokens != 42 {
		t.Errorf("input_tokens = %d, want 42", result.Usage.InputTokens)
	}
	if result.Usage.OutputTokens != 58 {
		t.Errorf("output_tokens = %d, want 58", result.Usage.OutputTokens)
	}
}

func TestOpenAIStreamToAnthropic_FirstChunk(t *testing.T) {
	content := "Hello"
	chunk := &StreamChunk{
		ID:      "chatcmpl-stream-123",
		Object:  "chat.completion.chunk",
		Created: 1234567890,
		Model:   "gpt-4o",
		Choices: []StreamChoice{
			{
				Index: 0,
				Delta: StreamDelta{
					Role:    "assistant",
					Content: &content,
				},
			},
		},
	}

	events, blockStarted := OpenAIStreamToAnthropic(chunk, true, false)
	if !blockStarted {
		t.Error("expected contentBlockStarted to be true after first content chunk")
	}

	// Should have: message_start, ping, content_block_start, content_block_delta
	if len(events) < 4 {
		t.Fatalf("events len = %d, want >= 4", len(events))
	}
	if events[0].Type != "message_start" {
		t.Errorf("events[0].type = %q, want %q", events[0].Type, "message_start")
	}
	if events[1].Type != "ping" {
		t.Errorf("events[1].type = %q, want %q", events[1].Type, "ping")
	}
	if events[2].Type != "content_block_start" {
		t.Errorf("events[2].type = %q, want %q", events[2].Type, "content_block_start")
	}
	if events[3].Type != "content_block_delta" {
		t.Errorf("events[3].type = %q, want %q", events[3].Type, "content_block_delta")
	}
}

func TestOpenAIStreamToAnthropic_ContentDelta(t *testing.T) {
	content := " world"
	chunk := &StreamChunk{
		ID:    "chatcmpl-stream-123",
		Model: "gpt-4o",
		Choices: []StreamChoice{
			{
				Index: 0,
				Delta: StreamDelta{Content: &content},
			},
		},
	}

	events, blockStarted := OpenAIStreamToAnthropic(chunk, false, true)
	if !blockStarted {
		t.Error("expected contentBlockStarted to remain true")
	}

	// Should have just a content_block_delta
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1", len(events))
	}
	if events[0].Type != "content_block_delta" {
		t.Errorf("events[0].type = %q, want %q", events[0].Type, "content_block_delta")
	}

	// Verify the delta contains the text
	var delta anthropicContentBlockDelta
	if err := json.Unmarshal(events[0].Data, &delta); err != nil {
		t.Fatalf("failed to unmarshal delta: %v", err)
	}
	if delta.Delta.Text != " world" {
		t.Errorf("delta text = %q, want %q", delta.Delta.Text, " world")
	}
}

func TestOpenAIStreamToAnthropic_FinalChunk(t *testing.T) {
	finishReason := "stop"
	chunk := &StreamChunk{
		ID:    "chatcmpl-stream-123",
		Model: "gpt-4o",
		Choices: []StreamChoice{
			{
				Index:        0,
				Delta:        StreamDelta{},
				FinishReason: &finishReason,
			},
		},
		Usage: &Usage{
			PromptTokens:     10,
			CompletionTokens: 5,
			TotalTokens:      15,
		},
	}

	events, _ := OpenAIStreamToAnthropic(chunk, false, true)

	// Should have: content_block_stop, message_delta, message_stop
	if len(events) < 3 {
		t.Fatalf("events len = %d, want >= 3", len(events))
	}

	// Find the event types
	typeMap := make(map[string]bool)
	for _, evt := range events {
		typeMap[evt.Type] = true
	}

	if !typeMap["content_block_stop"] {
		t.Error("missing content_block_stop event")
	}
	if !typeMap["message_delta"] {
		t.Error("missing message_delta event")
	}
	if !typeMap["message_stop"] {
		t.Error("missing message_stop event")
	}

	// Verify message_delta has stop_reason
	for _, evt := range events {
		if evt.Type == "message_delta" {
			var md anthropicMessageDelta
			if err := json.Unmarshal(evt.Data, &md); err != nil {
				t.Fatalf("failed to unmarshal message_delta: %v", err)
			}
			if md.Delta.StopReason == nil || *md.Delta.StopReason != "end_turn" {
				t.Errorf("stop_reason = %v, want end_turn", md.Delta.StopReason)
			}
			if md.Usage == nil {
				t.Error("usage is nil in message_delta")
			} else if md.Usage.OutputTokens != 5 {
				t.Errorf("output_tokens = %d, want 5", md.Usage.OutputTokens)
			}
		}
	}
}

func TestAnthropicToOpenAI_ToolChoice(t *testing.T) {
	tests := []struct {
		name       string
		toolChoice json.RawMessage
		wantJSON   string
	}{
		{
			name:       "auto",
			toolChoice: json.RawMessage(`{"type": "auto"}`),
			wantJSON:   `"auto"`,
		},
		{
			name:       "any",
			toolChoice: json.RawMessage(`{"type": "any"}`),
			wantJSON:   `"required"`,
		},
		{
			name:       "specific tool",
			toolChoice: json.RawMessage(`{"type": "tool", "name": "get_weather"}`),
			wantJSON:   ``, // check structure instead
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &AnthropicRequest{
				Model:      "claude-3-opus-20240229",
				MaxTokens:  1024,
				Messages:   []AnthropicMessage{{Role: "user", Content: json.RawMessage(`"test"`)}},
				ToolChoice: tt.toolChoice,
				Tools:      []AnthropicTool{{Name: "get_weather"}},
			}

			result, err := AnthropicToOpenAI(req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantJSON != "" {
				if string(result.ToolChoice) != tt.wantJSON {
					t.Errorf("tool_choice = %s, want %s", result.ToolChoice, tt.wantJSON)
				}
			} else if tt.name == "specific tool" {
				var parsed map[string]interface{}
				if err := json.Unmarshal(result.ToolChoice, &parsed); err != nil {
					t.Fatalf("failed to unmarshal tool_choice: %v", err)
				}
				if parsed["type"] != "function" {
					t.Errorf("tool_choice type = %v, want function", parsed["type"])
				}
			}
		})
	}
}

func TestAnthropicToOpenAI_NilRequest(t *testing.T) {
	_, err := AnthropicToOpenAI(nil)
	if err == nil {
		t.Error("expected error for nil request")
	}
}

func TestOpenAIToAnthropic_NilResponse(t *testing.T) {
	_, err := OpenAIToAnthropic(nil)
	if err == nil {
		t.Error("expected error for nil response")
	}
}

func TestOpenAIToAnthropic_EmptyChoices(t *testing.T) {
	resp := &ChatCompletionResponse{
		ID:      "chatcmpl-empty",
		Model:   "gpt-4o",
		Choices: []Choice{},
		Usage:   &Usage{PromptTokens: 5, CompletionTokens: 0, TotalTokens: 5},
	}

	result, err := OpenAIToAnthropic(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Content == nil {
		t.Error("content should not be nil (should be empty slice)")
	}
	if len(result.Content) != 0 {
		t.Errorf("content len = %d, want 0", len(result.Content))
	}
}

func TestAnthropicToOpenAI_StreamFlag(t *testing.T) {
	req := &AnthropicRequest{
		Model:     "claude-3-opus-20240229",
		MaxTokens: 100,
		Stream:    true,
		Messages:  []AnthropicMessage{{Role: "user", Content: json.RawMessage(`"Hello"`)}},
	}

	result, err := AnthropicToOpenAI(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsStreaming() {
		t.Error("expected streaming to be true")
	}
}

func TestAnthropicToOpenAI_MetadataUserID(t *testing.T) {
	req := &AnthropicRequest{
		Model:     "claude-3-opus-20240229",
		MaxTokens: 100,
		Messages:  []AnthropicMessage{{Role: "user", Content: json.RawMessage(`"Hello"`)}},
		Metadata:  &AnthropicMetadata{UserID: "user-abc"},
	}

	result, err := AnthropicToOpenAI(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.User != "user-abc" {
		t.Errorf("user = %q, want %q", result.User, "user-abc")
	}
}

func TestConvertIDPrefix(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"chatcmpl-abc123", "msg_abc123"},
		{"msg_already", "msg_already"},
		{"other-id", "msg_other-id"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := convertIDPrefix(tt.input)
			if got != tt.want {
				t.Errorf("convertIDPrefix(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
