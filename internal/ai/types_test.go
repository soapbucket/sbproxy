package ai

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChatCompletionRequest_JSONRoundtrip(t *testing.T) {
	temp := 0.7
	maxTokens := 1024
	stream := true

	req := ChatCompletionRequest{
		Model: "gpt-4",
		Messages: []Message{
			{Role: "system", Content: json.RawMessage(`"You are helpful."`)},
			{Role: "user", Content: json.RawMessage(`"Hello"`)},
		},
		Temperature:   &temp,
		MaxTokens:     &maxTokens,
		Stream:        &stream,
		StreamOptions: &StreamOptions{IncludeUsage: true},
		SBTags:        map[string]string{"env": "test"},
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded ChatCompletionRequest
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, "gpt-4", decoded.Model)
	assert.Len(t, decoded.Messages, 2)
	assert.Equal(t, "system", decoded.Messages[0].Role)
	assert.Equal(t, 0.7, *decoded.Temperature)
	assert.Equal(t, 1024, *decoded.MaxTokens)
	assert.True(t, decoded.IsStreaming())
	assert.Equal(t, "test", decoded.SBTags["env"])
}

func TestChatCompletionRequest_IsStreaming(t *testing.T) {
	tests := []struct {
		name     string
		stream   *bool
		expected bool
	}{
		{"nil", nil, false},
		{"true", boolPtr(true), true},
		{"false", boolPtr(false), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := ChatCompletionRequest{Stream: tt.stream}
			assert.Equal(t, tt.expected, req.IsStreaming())
		})
	}
}

func TestChatCompletionRequest_GetModel(t *testing.T) {
	req := ChatCompletionRequest{Model: "gpt-4"}
	assert.Equal(t, "gpt-4", req.GetModel("default"))

	req2 := ChatCompletionRequest{}
	assert.Equal(t, "default", req2.GetModel("default"))
}

func TestMessage_ContentString(t *testing.T) {
	tests := []struct {
		name    string
		content json.RawMessage
		want    string
	}{
		{"string content", json.RawMessage(`"hello world"`), "hello world"},
		{"empty", nil, ""},
		{"array text parts", json.RawMessage(`[{"type":"text","text":"hello "},{"type":"text","text":"world"}]`), "hello world"},
		{"array with image", json.RawMessage(`[{"type":"text","text":"describe this"},{"type":"image_url","image_url":{"url":"https://example.com/img.png"}}]`), "describe this"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := Message{Content: tt.content}
			assert.Equal(t, tt.want, m.ContentString())
		})
	}
}

func TestChatCompletionResponse_JSONFormat(t *testing.T) {
	finishReason := "stop"
	resp := ChatCompletionResponse{
		ID:      "chatcmpl-123",
		Object:  "chat.completion",
		Created: 1700000000,
		Model:   "gpt-4",
		Choices: []Choice{{
			Index: 0,
			Message: Message{
				Role:    "assistant",
				Content: json.RawMessage(`"Hello!"`),
			},
			FinishReason: &finishReason,
		}},
		Usage: &Usage{
			PromptTokens:     10,
			CompletionTokens: 5,
			TotalTokens:      15,
		},
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	// Verify it matches OpenAI wire format
	var raw map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))

	assert.Equal(t, "chatcmpl-123", raw["id"])
	assert.Equal(t, "chat.completion", raw["object"])
	assert.Equal(t, "gpt-4", raw["model"])

	choices := raw["choices"].([]any)
	assert.Len(t, choices, 1)
	choice := choices[0].(map[string]any)
	assert.Equal(t, "stop", choice["finish_reason"])
}

func TestStreamChunk_JSONFormat(t *testing.T) {
	text := "Hello"
	chunk := StreamChunk{
		ID:     "chatcmpl-123",
		Object: "chat.completion.chunk",
		Model:  "gpt-4",
		Choices: []StreamChoice{{
			Index: 0,
			Delta: StreamDelta{Content: &text},
		}},
	}

	data, err := json.Marshal(chunk)
	require.NoError(t, err)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))

	assert.Equal(t, "chat.completion.chunk", raw["object"])
	choices := raw["choices"].([]any)
	delta := choices[0].(map[string]any)["delta"].(map[string]any)
	assert.Equal(t, "Hello", delta["content"])
}

func TestToolCall_JSONRoundtrip(t *testing.T) {
	tc := ToolCall{
		ID:   "call_123",
		Type: "function",
		Function: ToolCallFunction{
			Name:      "get_weather",
			Arguments: `{"location":"NYC"}`,
		},
	}

	data, err := json.Marshal(tc)
	require.NoError(t, err)

	var decoded ToolCall
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, "call_123", decoded.ID)
	assert.Equal(t, "get_weather", decoded.Function.Name)
	assert.Equal(t, `{"location":"NYC"}`, decoded.Function.Arguments)
}

func TestEmbeddingRequest_JSONRoundtrip(t *testing.T) {
	req := EmbeddingRequest{
		Input: "Hello world",
		Model: "text-embedding-3-small",
	}
	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded EmbeddingRequest
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, "text-embedding-3-small", decoded.Model)
}

func TestModelInfo_JSONFormat(t *testing.T) {
	info := ModelInfo{
		ID:      "gpt-4",
		Object:  "model",
		Created: 1700000000,
		OwnedBy: "openai",
	}
	data, err := json.Marshal(info)
	require.NoError(t, err)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))
	assert.Equal(t, "gpt-4", raw["id"])
	assert.Equal(t, "model", raw["object"])
	assert.Equal(t, "openai", raw["owned_by"])
}

func boolPtr(b bool) *bool { return &b }
