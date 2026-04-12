package ai

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompletions_StringPrompt(t *testing.T) {
	msgs, err := parsePromptToMessages(json.RawMessage(`"Say hello"`))
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	assert.Equal(t, "user", msgs[0].Role)
	assert.Equal(t, "Say hello", msgs[0].ContentString())
}

func TestCompletions_ArrayPrompt(t *testing.T) {
	msgs, err := parsePromptToMessages(json.RawMessage(`["Hello", "World"]`))
	require.NoError(t, err)
	require.Len(t, msgs, 2)
	assert.Equal(t, "user", msgs[0].Role)
	assert.Equal(t, "Hello", msgs[0].ContentString())
	assert.Equal(t, "World", msgs[1].ContentString())
}

func TestCompletions_EmptyPrompt(t *testing.T) {
	_, err := parsePromptToMessages(nil)
	assert.Error(t, err)
}

func TestCompletions_ResponseFormat(t *testing.T) {
	finishReason := "stop"
	chatResp := &ChatCompletionResponse{
		ID:      "chatcmpl-abc123",
		Object:  "chat.completion",
		Created: 1700000000,
		Model:   "gpt-3.5-turbo-instruct",
		Choices: []Choice{{
			Index:        0,
			Message:      Message{Role: "assistant", Content: json.RawMessage(`"Hello!"`)},
			FinishReason: &finishReason,
		}},
		Usage: &Usage{
			PromptTokens:     5,
			CompletionTokens: 3,
			TotalTokens:      8,
		},
	}

	legacy, err := chatResponseToLegacy(chatResp)
	require.NoError(t, err)

	assert.Equal(t, "text_completion", legacy.Object)
	assert.Equal(t, "cmpl-abc123", legacy.ID)
	assert.Equal(t, int64(1700000000), legacy.Created)
	assert.Equal(t, "gpt-3.5-turbo-instruct", legacy.Model)
	require.Len(t, legacy.Choices, 1)
	assert.Equal(t, "Hello!", legacy.Choices[0].Text)
	assert.Equal(t, 0, legacy.Choices[0].Index)
	assert.Equal(t, "stop", *legacy.Choices[0].FinishReason)
	require.NotNil(t, legacy.Usage)
	assert.Equal(t, 5, legacy.Usage.PromptTokens)
	assert.Equal(t, 3, legacy.Usage.CompletionTokens)
	assert.Equal(t, 8, legacy.Usage.TotalTokens)
}

func TestCompletions_IDPrefix(t *testing.T) {
	tests := []struct {
		name     string
		inputID  string
		expected string
	}{
		{"chatcmpl prefix", "chatcmpl-abc", "cmpl-abc"},
		{"empty ID generates cmpl prefix", "", "cmpl-"},
		{"other prefix kept", "other-123", "other-123"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &ChatCompletionResponse{
				ID:      tt.inputID,
				Object:  "chat.completion",
				Created: 1700000000,
				Model:   "gpt-4",
			}
			legacy, err := chatResponseToLegacy(resp)
			require.NoError(t, err)
			if tt.inputID == "" {
				assert.True(t, strings.HasPrefix(legacy.ID, "cmpl-"), "expected cmpl- prefix, got %s", legacy.ID)
			} else {
				assert.Equal(t, tt.expected, legacy.ID)
			}
		})
	}
}

func TestCompletions_StreamChunkFormat(t *testing.T) {
	text := "Hello"
	finishReason := "stop"
	chunk := &StreamChunk{
		ID:      "chatcmpl-stream1",
		Object:  "chat.completion.chunk",
		Created: 1700000000,
		Model:   "gpt-3.5-turbo-instruct",
		Choices: []StreamChoice{{
			Index:        0,
			Delta:        StreamDelta{Content: &text},
			FinishReason: &finishReason,
		}},
	}

	legacy := chatStreamChunkToLegacy(chunk)

	assert.Equal(t, "text_completion", legacy.Object)
	assert.Equal(t, "cmpl-stream1", legacy.ID)
	assert.Equal(t, int64(1700000000), legacy.Created)
	assert.Equal(t, "gpt-3.5-turbo-instruct", legacy.Model)
	require.Len(t, legacy.Choices, 1)
	assert.Equal(t, "Hello", legacy.Choices[0].Text)
	assert.Equal(t, 0, legacy.Choices[0].Index)
	assert.Equal(t, "stop", *legacy.Choices[0].FinishReason)
}

func TestCompletions_StreamChunkUsage(t *testing.T) {
	chunk := &StreamChunk{
		ID:      "chatcmpl-u1",
		Object:  "chat.completion.chunk",
		Created: 1700000000,
		Model:   "gpt-4",
		Usage: &Usage{
			PromptTokens:     10,
			CompletionTokens: 5,
			TotalTokens:      15,
		},
	}

	legacy := chatStreamChunkToLegacy(chunk)

	require.NotNil(t, legacy.Usage)
	assert.Equal(t, 10, legacy.Usage.PromptTokens)
	assert.Equal(t, 5, legacy.Usage.CompletionTokens)
	assert.Equal(t, 15, legacy.Usage.TotalTokens)
}

func TestCompletions_Handler_NonStreaming(t *testing.T) {
	finishReason := "stop"
	mp := &mockProvider{
		name: "test",
		chatResp: &ChatCompletionResponse{
			ID:      "chatcmpl-legacy1",
			Object:  "chat.completion",
			Created: 1700000000,
			Model:   "gpt-3.5-turbo-instruct",
			Choices: []Choice{{
				Index:        0,
				Message:      Message{Role: "assistant", Content: json.RawMessage(`"Hello there!"`)},
				FinishReason: &finishReason,
			}},
			Usage: &Usage{
				PromptTokens:     4,
				CompletionTokens: 2,
				TotalTokens:      6,
			},
		},
	}

	cfg := &ProviderConfig{Name: "test"}
	h := newTestHandler(t, mp, cfg)

	reqBody := `{"model":"gpt-3.5-turbo-instruct","prompt":"Say hello","max_tokens":100}`
	req := httptest.NewRequest(http.MethodPost, "/v1/completions", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var resp LegacyCompletionResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "cmpl-legacy1", resp.ID)
	assert.Equal(t, "text_completion", resp.Object)
	assert.Equal(t, "gpt-3.5-turbo-instruct", resp.Model)
	require.Len(t, resp.Choices, 1)
	assert.Equal(t, "Hello there!", resp.Choices[0].Text)
	assert.Equal(t, "stop", *resp.Choices[0].FinishReason)
	require.NotNil(t, resp.Usage)
	assert.Equal(t, 4, resp.Usage.PromptTokens)
	assert.Equal(t, 2, resp.Usage.CompletionTokens)
	assert.Equal(t, 6, resp.Usage.TotalTokens)
}

func TestCompletions_Handler_ArrayPrompt(t *testing.T) {
	finishReason := "stop"
	mp := &mockProvider{
		name: "test",
		chatResp: &ChatCompletionResponse{
			ID:      "chatcmpl-arr1",
			Object:  "chat.completion",
			Created: 1700000000,
			Model:   "gpt-3.5-turbo-instruct",
			Choices: []Choice{{
				Index:        0,
				Message:      Message{Role: "assistant", Content: json.RawMessage(`"Response"`)},
				FinishReason: &finishReason,
			}},
		},
	}

	cfg := &ProviderConfig{Name: "test"}
	h := newTestHandler(t, mp, cfg)

	reqBody := `{"model":"gpt-3.5-turbo-instruct","prompt":["Hello","World"],"max_tokens":50}`
	req := httptest.NewRequest(http.MethodPost, "/v1/completions", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify the chat request received two user messages from the array prompt.
	require.NotNil(t, mp.lastChatReq)
	require.Len(t, mp.lastChatReq.Messages, 2)
	assert.Equal(t, "Hello", mp.lastChatReq.Messages[0].ContentString())
	assert.Equal(t, "World", mp.lastChatReq.Messages[1].ContentString())
}

func TestCompletions_Handler_Streaming(t *testing.T) {
	text1 := "Hello"
	text2 := " world"
	finishReason := "stop"
	mp := &mockProvider{
		name: "test",
		streamChunks: []*StreamChunk{
			{
				ID:      "chatcmpl-s1",
				Object:  "chat.completion.chunk",
				Created: 1700000000,
				Model:   "gpt-3.5-turbo-instruct",
				Choices: []StreamChoice{{
					Index: 0,
					Delta: StreamDelta{Content: &text1},
				}},
			},
			{
				ID:      "chatcmpl-s1",
				Object:  "chat.completion.chunk",
				Created: 1700000000,
				Model:   "gpt-3.5-turbo-instruct",
				Choices: []StreamChoice{{
					Index: 0,
					Delta: StreamDelta{Content: &text2},
				}},
			},
			{
				ID:      "chatcmpl-s1",
				Object:  "chat.completion.chunk",
				Created: 1700000000,
				Model:   "gpt-3.5-turbo-instruct",
				Choices: []StreamChoice{{
					Index:        0,
					Delta:        StreamDelta{},
					FinishReason: &finishReason,
				}},
			},
		},
	}

	cfg := &ProviderConfig{Name: "test"}
	h := newTestHandler(t, mp, cfg)

	reqBody := `{"model":"gpt-3.5-turbo-instruct","prompt":"Say hello","stream":true}`
	req := httptest.NewRequest(http.MethodPost, "/v1/completions", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/event-stream", w.Header().Get("Content-Type"))

	body := w.Body.String()
	// Verify chunks contain text_completion object type
	assert.Contains(t, body, `"object":"text_completion"`)
	// Verify chunks contain cmpl- prefix
	assert.Contains(t, body, `"cmpl-s1"`)
	// Verify text field is present
	assert.Contains(t, body, `"text":"Hello"`)
	assert.Contains(t, body, `"text":" world"`)
	// Verify [DONE] terminator
	assert.Contains(t, body, "data: [DONE]")
}

func TestCompletions_Handler_MethodNotAllowed(t *testing.T) {
	mp := &mockProvider{name: "test"}
	cfg := &ProviderConfig{Name: "test"}
	h := newTestHandler(t, mp, cfg)

	req := httptest.NewRequest(http.MethodGet, "/v1/completions", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestCompletions_Handler_MissingModel(t *testing.T) {
	mp := &mockProvider{name: "test"}
	cfg := &ProviderConfig{Name: "test"}
	h := newTestHandler(t, mp, cfg)

	reqBody := `{"prompt":"Hello"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/completions", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCompletions_Handler_InvalidPrompt(t *testing.T) {
	mp := &mockProvider{name: "test"}
	cfg := &ProviderConfig{Name: "test"}
	h := newTestHandler(t, mp, cfg)

	reqBody := `{"model":"gpt-4","prompt":123}`
	req := httptest.NewRequest(http.MethodPost, "/v1/completions", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCompletions_LegacyToChatRequest_PassesParams(t *testing.T) {
	temp := 0.7
	topP := 0.9
	n := 2
	maxTokens := 100
	presencePenalty := 0.5
	frequencyPenalty := 0.3

	legacyReq := &LegacyCompletionRequest{
		Model:            "gpt-3.5-turbo-instruct",
		Prompt:           json.RawMessage(`"test"`),
		Temperature:      &temp,
		TopP:             &topP,
		N:                &n,
		MaxTokens:        &maxTokens,
		PresencePenalty:  &presencePenalty,
		FrequencyPenalty: &frequencyPenalty,
		Stop:             json.RawMessage(`"END"`),
		User:             "test-user",
	}

	chatReq, err := legacyToChatRequest(legacyReq)
	require.NoError(t, err)

	assert.Equal(t, "gpt-3.5-turbo-instruct", chatReq.Model)
	assert.Equal(t, 0.7, *chatReq.Temperature)
	assert.Equal(t, 0.9, *chatReq.TopP)
	assert.Equal(t, 2, *chatReq.N)
	assert.Equal(t, 100, *chatReq.MaxTokens)
	assert.Equal(t, 0.5, *chatReq.PresencePenalty)
	assert.Equal(t, 0.3, *chatReq.FrequencyPenalty)
	assert.Equal(t, `"END"`, string(chatReq.Stop))
	assert.Equal(t, "test-user", chatReq.User)
}

func TestCompletions_NewLegacyCompletionResponse(t *testing.T) {
	usage := &Usage{PromptTokens: 10, CompletionTokens: 20, TotalTokens: 30}
	resp, err := NewLegacyCompletionResponse("gpt-4", "Hello!", "stop", usage)
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(resp.ID, "cmpl-"))
	assert.Equal(t, "text_completion", resp.Object)
	assert.Equal(t, "gpt-4", resp.Model)
	require.Len(t, resp.Choices, 1)
	assert.Equal(t, "Hello!", resp.Choices[0].Text)
	assert.Equal(t, "stop", *resp.Choices[0].FinishReason)
	assert.Equal(t, usage, resp.Usage)
}
