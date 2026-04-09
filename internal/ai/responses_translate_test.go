package ai

import (
	"context"
	"testing"
	"time"

	json "github.com/goccy/go-json"
)

func TestResponseToChat_StringInput(t *testing.T) {
	req := &CreateResponseRequest{
		Model: "gpt-4o",
		Input: json.RawMessage(`"Hello, how are you?"`),
	}

	chatReq, err := ResponseToChat(req, nil)
	if err != nil {
		t.Fatalf("ResponseToChat failed: %v", err)
	}

	if chatReq.Model != "gpt-4o" {
		t.Errorf("Expected model gpt-4o, got %s", chatReq.Model)
	}
	if len(chatReq.Messages) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(chatReq.Messages))
	}
	if chatReq.Messages[0].Role != "user" {
		t.Errorf("Expected role user, got %s", chatReq.Messages[0].Role)
	}
	if chatReq.Messages[0].ContentString() != "Hello, how are you?" {
		t.Errorf("Expected content 'Hello, how are you?', got %q", chatReq.Messages[0].ContentString())
	}
}

func TestResponseToChat_MessageInput(t *testing.T) {
	input := `[{"role": "user", "content": "What is 2+2?"}, {"role": "assistant", "content": "4"}, {"role": "user", "content": "And 3+3?"}]`
	req := &CreateResponseRequest{
		Model: "gpt-4o",
		Input: json.RawMessage(input),
	}

	chatReq, err := ResponseToChat(req, nil)
	if err != nil {
		t.Fatalf("ResponseToChat failed: %v", err)
	}

	if len(chatReq.Messages) != 3 {
		t.Fatalf("Expected 3 messages, got %d", len(chatReq.Messages))
	}
	if chatReq.Messages[0].Role != "user" {
		t.Errorf("Expected first message role user, got %s", chatReq.Messages[0].Role)
	}
	if chatReq.Messages[1].Role != "assistant" {
		t.Errorf("Expected second message role assistant, got %s", chatReq.Messages[1].Role)
	}
	if chatReq.Messages[2].ContentString() != "And 3+3?" {
		t.Errorf("Expected third message content 'And 3+3?', got %q", chatReq.Messages[2].ContentString())
	}
}

func TestResponseToChat_WithInstructions(t *testing.T) {
	req := &CreateResponseRequest{
		Model:        "gpt-4o",
		Input:        json.RawMessage(`"Hello"`),
		Instructions: "You are a helpful assistant.",
	}

	chatReq, err := ResponseToChat(req, nil)
	if err != nil {
		t.Fatalf("ResponseToChat failed: %v", err)
	}

	if len(chatReq.Messages) != 2 {
		t.Fatalf("Expected 2 messages (system + user), got %d", len(chatReq.Messages))
	}
	if chatReq.Messages[0].Role != "system" {
		t.Errorf("Expected first message role system, got %s", chatReq.Messages[0].Role)
	}
	if chatReq.Messages[0].ContentString() != "You are a helpful assistant." {
		t.Errorf("Expected system message content, got %q", chatReq.Messages[0].ContentString())
	}
	if chatReq.Messages[1].Role != "user" {
		t.Errorf("Expected second message role user, got %s", chatReq.Messages[1].Role)
	}
}

func TestResponseToChat_WithTools(t *testing.T) {
	req := &CreateResponseRequest{
		Model: "gpt-4o",
		Input: json.RawMessage(`"What is the weather?"`),
		Tools: []Tool{
			{
				Type: "function",
				Function: ToolFunction{
					Name:        "get_weather",
					Description: "Get the weather",
					Parameters:  json.RawMessage(`{"type": "object", "properties": {"location": {"type": "string"}}}`),
				},
			},
		},
	}

	chatReq, err := ResponseToChat(req, nil)
	if err != nil {
		t.Fatalf("ResponseToChat failed: %v", err)
	}

	if len(chatReq.Tools) != 1 {
		t.Fatalf("Expected 1 tool, got %d", len(chatReq.Tools))
	}
	if chatReq.Tools[0].Function.Name != "get_weather" {
		t.Errorf("Expected tool name get_weather, got %s", chatReq.Tools[0].Function.Name)
	}
}

func TestResponseToChat_WithTemperature(t *testing.T) {
	temp := 0.7
	topP := 0.9
	req := &CreateResponseRequest{
		Model:           "gpt-4o",
		Input:           json.RawMessage(`"Hello"`),
		Temperature:     &temp,
		TopP:            &topP,
		MaxOutputTokens: 100,
	}

	chatReq, err := ResponseToChat(req, nil)
	if err != nil {
		t.Fatalf("ResponseToChat failed: %v", err)
	}

	if chatReq.Temperature == nil || *chatReq.Temperature != 0.7 {
		t.Error("Expected temperature 0.7")
	}
	if chatReq.TopP == nil || *chatReq.TopP != 0.9 {
		t.Error("Expected top_p 0.9")
	}
	if chatReq.MaxTokens == nil || *chatReq.MaxTokens != 100 {
		t.Error("Expected max_tokens 100")
	}
}

func TestResponseToChat_WithPreviousResponse(t *testing.T) {
	store := NewMemoryResponseStore(100, time.Hour)
	defer store.Close()

	// Store a previous response
	prev := &ResponseObject{
		ID:        "resp_prev",
		Object:    "response",
		CreatedAt: time.Now().Unix(),
		Status:    ResponseStatusCompleted,
		Model:     "gpt-4o",
		Output: []OutputItem{
			{
				Type: "message",
				ID:   "msg_prev",
				Role: "assistant",
				Content: []ContentItem{
					{Type: "output_text", Text: "I'm doing well!"},
				},
			},
		},
	}
	_ = store.Store(context.Background(), prev)

	req := &CreateResponseRequest{
		Model:              "gpt-4o",
		Input:              json.RawMessage(`"Follow up question"`),
		PreviousResponseID: "resp_prev",
	}

	chatReq, err := ResponseToChat(req, store)
	if err != nil {
		t.Fatalf("ResponseToChat failed: %v", err)
	}

	// Should have: previous assistant message + new user message
	if len(chatReq.Messages) != 2 {
		t.Fatalf("Expected 2 messages (prev assistant + new user), got %d", len(chatReq.Messages))
	}
	if chatReq.Messages[0].Role != "assistant" {
		t.Errorf("Expected first message role assistant (from previous), got %s", chatReq.Messages[0].Role)
	}
	if chatReq.Messages[0].ContentString() != "I'm doing well!" {
		t.Errorf("Expected previous response content, got %q", chatReq.Messages[0].ContentString())
	}
	if chatReq.Messages[1].Role != "user" {
		t.Errorf("Expected second message role user, got %s", chatReq.Messages[1].Role)
	}
}

func TestChatToResponse_Success(t *testing.T) {
	stopReason := "stop"
	chatResp := &ChatCompletionResponse{
		ID:      "chatcmpl-abc123",
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   "gpt-4o",
		Choices: []Choice{
			{
				Index: 0,
				Message: Message{
					Role:    "assistant",
					Content: json.RawMessage(`"Hello! How can I help you?"`),
				},
				FinishReason: &stopReason,
			},
		},
		Usage: &Usage{
			PromptTokens:     10,
			CompletionTokens: 8,
			TotalTokens:      18,
		},
	}

	req := &CreateResponseRequest{
		Model:    "gpt-4o",
		Metadata: map[string]string{"env": "test"},
	}

	resp := ChatToResponse(chatResp, req)

	if resp.Object != "response" {
		t.Errorf("Expected object 'response', got %q", resp.Object)
	}
	if resp.Status != ResponseStatusCompleted {
		t.Errorf("Expected status completed, got %s", resp.Status)
	}
	if resp.Model != "gpt-4o" {
		t.Errorf("Expected model gpt-4o, got %s", resp.Model)
	}
	if len(resp.Output) != 1 {
		t.Fatalf("Expected 1 output item, got %d", len(resp.Output))
	}
	if resp.Output[0].Type != "message" {
		t.Errorf("Expected output type message, got %s", resp.Output[0].Type)
	}
	if resp.Output[0].Content[0].Text != "Hello! How can I help you?" {
		t.Errorf("Expected output text, got %q", resp.Output[0].Content[0].Text)
	}
	if resp.Usage == nil {
		t.Fatal("Expected usage")
	}
	if resp.Usage.InputTokens != 10 {
		t.Errorf("Expected input_tokens 10, got %d", resp.Usage.InputTokens)
	}
	if resp.Usage.OutputTokens != 8 {
		t.Errorf("Expected output_tokens 8, got %d", resp.Usage.OutputTokens)
	}
	if resp.Metadata["env"] != "test" {
		t.Errorf("Expected metadata env=test")
	}
}

func TestChatToResponse_ToolCalls(t *testing.T) {
	stopReason := "tool_calls"
	chatResp := &ChatCompletionResponse{
		ID:    "chatcmpl-tools",
		Model: "gpt-4o",
		Choices: []Choice{
			{
				Index: 0,
				Message: Message{
					Role:    "assistant",
					Content: json.RawMessage(`""`),
					ToolCalls: []ToolCall{
						{
							ID:   "call_123",
							Type: "function",
							Function: ToolCallFunction{
								Name:      "get_weather",
								Arguments: `{"location": "NYC"}`,
							},
						},
					},
				},
				FinishReason: &stopReason,
			},
		},
	}

	req := &CreateResponseRequest{Model: "gpt-4o"}
	resp := ChatToResponse(chatResp, req)

	// Should have function_call output item for tool call
	foundFuncCall := false
	for _, item := range resp.Output {
		if item.Type == "function_call" {
			foundFuncCall = true
			if item.ID != "call_123" {
				t.Errorf("Expected function call ID call_123, got %s", item.ID)
			}
		}
	}
	if !foundFuncCall {
		t.Error("Expected function_call output item for tool call")
	}
}

func TestChatToResponse_StopReasons(t *testing.T) {
	tests := []struct {
		name         string
		finishReason string
		wantStatus   ResponseStatus
		wantError    bool
	}{
		{"stop", "stop", ResponseStatusCompleted, false},
		{"length", "length", ResponseStatusCompleted, false},
		{"content_filter", "content_filter", ResponseStatusFailed, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason := tt.finishReason
			chatResp := &ChatCompletionResponse{
				ID:    "chatcmpl-test",
				Model: "gpt-4o",
				Choices: []Choice{
					{
						Index: 0,
						Message: Message{
							Role:    "assistant",
							Content: json.RawMessage(`"test"`),
						},
						FinishReason: &reason,
					},
				},
			}

			req := &CreateResponseRequest{Model: "gpt-4o"}
			resp := ChatToResponse(chatResp, req)

			if resp.Status != tt.wantStatus {
				t.Errorf("Expected status %s, got %s", tt.wantStatus, resp.Status)
			}
			if tt.wantError && resp.Error == nil {
				t.Error("Expected error to be set")
			}
			if !tt.wantError && resp.Error != nil {
				t.Error("Expected no error")
			}
		})
	}
}

func TestChatToResponse_WithCachedTokens(t *testing.T) {
	stopReason := "stop"
	chatResp := &ChatCompletionResponse{
		ID:    "chatcmpl-cached",
		Model: "gpt-4o",
		Choices: []Choice{
			{
				Index: 0,
				Message: Message{
					Role:    "assistant",
					Content: json.RawMessage(`"Hello"`),
				},
				FinishReason: &stopReason,
			},
		},
		Usage: &Usage{
			PromptTokens:       10,
			CompletionTokens:   5,
			TotalTokens:        15,
			PromptTokensCached: 3,
		},
	}

	req := &CreateResponseRequest{Model: "gpt-4o"}
	resp := ChatToResponse(chatResp, req)

	if resp.Usage == nil {
		t.Fatal("Expected usage")
	}
	if resp.Usage.InputDetails == nil {
		t.Fatal("Expected input details for cached tokens")
	}
	if resp.Usage.InputDetails.CachedTokens != 3 {
		t.Errorf("Expected cached_tokens 3, got %d", resp.Usage.InputDetails.CachedTokens)
	}
}
