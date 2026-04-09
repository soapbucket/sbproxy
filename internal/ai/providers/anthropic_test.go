package providers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnthropic_ChatCompletion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/messages", r.URL.Path)
		assert.Equal(t, "test-key", r.Header.Get("x-api-key"))
		assert.Equal(t, "2023-06-01", r.Header.Get("anthropic-version"))

		// Verify request format
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		json.Unmarshal(body, &req)
		assert.Equal(t, "claude-3-5-sonnet-20241022", req["model"])
		assert.Equal(t, "You are helpful.", req["system"])
		assert.Equal(t, float64(4096), req["max_tokens"])

		messages := req["messages"].([]any)
		assert.Len(t, messages, 1) // system message extracted
		assert.Equal(t, "user", messages[0].(map[string]any)["role"])

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(anthropicResponse{
			ID:         "msg_123",
			Type:       "message",
			Role:       "assistant",
			Model:      "claude-3-5-sonnet-20241022",
			StopReason: "end_turn",
			Content: []anthropicContentBlock{
				{Type: "text", Text: "Hello!"},
			},
			Usage: anthropicUsage{InputTokens: 10, OutputTokens: 5},
		})
	}))
	defer server.Close()

	p := NewAnthropic(server.Client())
	cfg := &ai.ProviderConfig{
		Name:    "anthropic",
		APIKey:  "test-key",
		BaseURL: server.URL + "/v1",
	}

	resp, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model: "claude-3-5-sonnet-20241022",
		Messages: []ai.Message{
			{Role: "system", Content: json.RawMessage(`"You are helpful."`)},
			{Role: "user", Content: json.RawMessage(`"Hi"`)},
		},
	}, cfg)

	require.NoError(t, err)
	assert.Equal(t, "msg_123", resp.ID)
	assert.Equal(t, "chat.completion", resp.Object)
	assert.Len(t, resp.Choices, 1)
	assert.Equal(t, "assistant", resp.Choices[0].Message.Role)
	assert.Equal(t, "stop", *resp.Choices[0].FinishReason)
	assert.Equal(t, 10, resp.Usage.PromptTokens)
	assert.Equal(t, 5, resp.Usage.CompletionTokens)
	assert.Equal(t, 15, resp.Usage.TotalTokens)
}

func TestAnthropic_ToolUseConversion(t *testing.T) {
	var receivedBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedBody)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(anthropicResponse{
			ID:         "msg_123",
			Type:       "message",
			Role:       "assistant",
			StopReason: "tool_use",
			Content: []anthropicContentBlock{
				{Type: "text", Text: "Let me check the weather."},
				{Type: "tool_use", ID: "toolu_123", Name: "get_weather", Input: json.RawMessage(`{"location":"NYC"}`)},
			},
			Usage: anthropicUsage{InputTokens: 20, OutputTokens: 15},
		})
	}))
	defer server.Close()

	p := NewAnthropic(server.Client())
	cfg := &ai.ProviderConfig{
		Name:    "anthropic",
		APIKey:  "test-key",
		BaseURL: server.URL + "/v1",
	}

	resp, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model: "claude-3-5-sonnet-20241022",
		Messages: []ai.Message{
			{Role: "user", Content: json.RawMessage(`"What's the weather in NYC?"`)},
		},
		Tools: []ai.Tool{{
			Type: "function",
			Function: ai.ToolFunction{
				Name:        "get_weather",
				Description: "Get weather for a location",
				Parameters:  json.RawMessage(`{"type":"object","properties":{"location":{"type":"string"}}}`),
			},
		}},
	}, cfg)

	require.NoError(t, err)
	assert.Equal(t, "tool_calls", *resp.Choices[0].FinishReason)
	assert.Len(t, resp.Choices[0].Message.ToolCalls, 1)
	assert.Equal(t, "get_weather", resp.Choices[0].Message.ToolCalls[0].Function.Name)
	assert.Equal(t, "toolu_123", resp.Choices[0].Message.ToolCalls[0].ID)

	// Verify tools were converted to Anthropic format
	tools := receivedBody["tools"].([]any)
	assert.Len(t, tools, 1)
	tool := tools[0].(map[string]any)
	assert.Equal(t, "get_weather", tool["name"])
	assert.NotNil(t, tool["input_schema"])
}

func TestAnthropic_ToolResultConversion(t *testing.T) {
	var receivedBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedBody)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(anthropicResponse{
			ID: "msg_456", Type: "message", Role: "assistant", StopReason: "end_turn",
			Content: []anthropicContentBlock{{Type: "text", Text: "It's sunny in NYC!"}},
			Usage:   anthropicUsage{InputTokens: 30, OutputTokens: 10},
		})
	}))
	defer server.Close()

	p := NewAnthropic(server.Client())
	cfg := &ai.ProviderConfig{Name: "anthropic", APIKey: "test-key", BaseURL: server.URL + "/v1"}

	_, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model: "claude-3-5-sonnet-20241022",
		Messages: []ai.Message{
			{Role: "user", Content: json.RawMessage(`"What's the weather?"`)},
			{
				Role:    "assistant",
				Content: json.RawMessage(`""`),
				ToolCalls: []ai.ToolCall{{
					ID: "toolu_123", Type: "function",
					Function: ai.ToolCallFunction{Name: "get_weather", Arguments: `{"location":"NYC"}`},
				}},
			},
			{
				Role:       "tool",
				Content:    json.RawMessage(`"Sunny, 72°F"`),
				ToolCallID: "toolu_123",
			},
		},
	}, cfg)
	require.NoError(t, err)

	// Verify tool result was converted properly
	messages := receivedBody["messages"].([]any)
	assert.Len(t, messages, 3)
	// Last message should be user role with tool_result content
	toolResultMsg := messages[2].(map[string]any)
	assert.Equal(t, "user", toolResultMsg["role"])
	content := toolResultMsg["content"].([]any)
	block := content[0].(map[string]any)
	assert.Equal(t, "tool_result", block["type"])
	assert.Equal(t, "toolu_123", block["tool_use_id"])
}

func TestAnthropic_Stream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)

		events := []string{
			`event: message_start` + "\n" + `data: {"type":"message_start","message":{"id":"msg_123","type":"message","role":"assistant","model":"claude-3-5-sonnet-20241022","content":[],"stop_reason":null,"usage":{"input_tokens":10,"output_tokens":0}}}`,
			`event: content_block_start` + "\n" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
			`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}`,
			`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" world"}}`,
			`event: content_block_stop` + "\n" + `data: {"type":"content_block_stop","index":0}`,
			`event: message_delta` + "\n" + `data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":5}}`,
			`event: message_stop` + "\n" + `data: {"type":"message_stop"}`,
		}
		for _, event := range events {
			w.Write([]byte(event + "\n\n"))
			flusher.Flush()
		}
	}))
	defer server.Close()

	p := NewAnthropic(server.Client())
	cfg := &ai.ProviderConfig{Name: "anthropic", APIKey: "test-key", BaseURL: server.URL + "/v1"}

	stream, err := p.ChatCompletionStream(t.Context(), &ai.ChatCompletionRequest{
		Model:    "claude-3-5-sonnet-20241022",
		Messages: []ai.Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
	}, cfg)
	require.NoError(t, err)
	defer stream.Close()

	// message_start -> role chunk
	chunk, err := stream.Read()
	require.NoError(t, err)
	assert.Equal(t, "assistant", chunk.Choices[0].Delta.Role)
	assert.Equal(t, "msg_123", chunk.ID)

	// content_block_start for text -> skip (no chunk emitted for text start)
	// content_block_delta -> text "Hello"
	chunk, err = stream.Read()
	require.NoError(t, err)
	assert.Equal(t, "Hello", *chunk.Choices[0].Delta.Content)

	// content_block_delta -> text " world"
	chunk, err = stream.Read()
	require.NoError(t, err)
	assert.Equal(t, " world", *chunk.Choices[0].Delta.Content)

	// message_delta -> finish_reason
	chunk, err = stream.Read()
	require.NoError(t, err)
	assert.Equal(t, "stop", *chunk.Choices[0].FinishReason)
	assert.Equal(t, 5, chunk.Usage.CompletionTokens)

	// message_stop -> EOF
	_, err = stream.Read()
	assert.Equal(t, io.EOF, err)
}

func TestAnthropic_StopReasonMapping(t *testing.T) {
	tests := []struct {
		anthropic string
		openai    string
	}{
		{"end_turn", "stop"},
		{"max_tokens", "length"},
		{"stop_sequence", "stop"},
		{"tool_use", "tool_calls"},
		{"unknown", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.anthropic, func(t *testing.T) {
			assert.Equal(t, tt.openai, mapAnthropicStopReason(tt.anthropic))
		})
	}
}

func TestAnthropic_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"type":"error","error":{"type":"invalid_request_error","message":"max_tokens: field required"}}`))
	}))
	defer server.Close()

	p := NewAnthropic(server.Client())
	cfg := &ai.ProviderConfig{Name: "anthropic", APIKey: "test-key", BaseURL: server.URL + "/v1"}

	_, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model:    "claude-3-5-sonnet-20241022",
		Messages: []ai.Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
	}, cfg)

	require.Error(t, err)
	aiErr, ok := err.(*ai.AIError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, aiErr.StatusCode)
	assert.Equal(t, "invalid_request_error", aiErr.Type)
}

func TestAnthropic_MaxTokensDefault(t *testing.T) {
	var receivedBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(anthropicResponse{
			ID: "msg_1", Type: "message", Role: "assistant", StopReason: "end_turn",
			Content: []anthropicContentBlock{{Type: "text", Text: "Hi"}},
			Usage:   anthropicUsage{InputTokens: 5, OutputTokens: 1},
		})
	}))
	defer server.Close()

	p := NewAnthropic(server.Client())
	cfg := &ai.ProviderConfig{Name: "anthropic", APIKey: "test-key", BaseURL: server.URL + "/v1"}

	// No MaxTokens set — should default to 4096
	_, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model:    "claude-3-5-sonnet-20241022",
		Messages: []ai.Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
	}, cfg)
	require.NoError(t, err)
	assert.Equal(t, float64(4096), receivedBody["max_tokens"])
}

func TestAnthropic_ListModels(t *testing.T) {
	p := NewAnthropic(http.DefaultClient)
	cfg := &ai.ProviderConfig{Name: "anthropic"}

	models, err := p.ListModels(t.Context(), cfg)
	require.NoError(t, err)
	assert.Greater(t, len(models), 0)

	// Verify at least one expected model
	found := false
	for _, m := range models {
		if m.OwnedBy == "anthropic" {
			found = true
			break
		}
	}
	assert.True(t, found)
}
