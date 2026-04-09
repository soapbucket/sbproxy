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

func TestCohereProvider(t *testing.T) {
	cfg := &ai.ProviderConfig{Name: "cohere", Type: "cohere"}
	p, err := ai.NewProvider(cfg, http.DefaultClient)
	require.NoError(t, err, "failed to create cohere provider")

	assert.Equal(t, "cohere", p.Name())
	assert.True(t, p.SupportsStreaming(), "expected streaming support")
	assert.True(t, p.SupportsEmbeddings(), "expected embeddings support")
}

func TestCohere_ChatCompletion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v2/chat", r.URL.Path)
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))

		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		json.Unmarshal(body, &req)
		assert.Equal(t, "command-r-plus", req["model"])

		messages := req["messages"].([]any)
		assert.Len(t, messages, 2)
		assert.Equal(t, "system", messages[0].(map[string]any)["role"])
		assert.Equal(t, "user", messages[1].(map[string]any)["role"])

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cohereResponse{
			ID:           "chat-123",
			FinishReason: "COMPLETE",
			Model:        "command-r-plus",
			Message: cohereResponseMessage{
				Role: "assistant",
				Content: []cohereContentBlock{
					{Type: "text", Text: "Hello!"},
				},
			},
			Usage: cohereUsage{
				Tokens: &cohereTokens{InputTokens: 10, OutputTokens: 5},
			},
		})
	}))
	defer server.Close()

	p := NewCohere(server.Client())
	cfg := &ai.ProviderConfig{
		Name:    "cohere",
		APIKey:  "test-key",
		BaseURL: server.URL + "/v2",
	}

	resp, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model: "command-r-plus",
		Messages: []ai.Message{
			{Role: "system", Content: json.RawMessage(`"You are helpful."`)},
			{Role: "user", Content: json.RawMessage(`"Hi"`)},
		},
	}, cfg)

	require.NoError(t, err)
	assert.Equal(t, "chat-123", resp.ID)
	assert.Equal(t, "chat.completion", resp.Object)
	assert.Len(t, resp.Choices, 1)
	assert.Equal(t, "assistant", resp.Choices[0].Message.Role)
	assert.Equal(t, "stop", *resp.Choices[0].FinishReason)
	assert.Equal(t, 10, resp.Usage.PromptTokens)
	assert.Equal(t, 5, resp.Usage.CompletionTokens)
	assert.Equal(t, 15, resp.Usage.TotalTokens)
}

func TestCohere_ChatCompletionWithBilledUnits(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cohereResponse{
			ID:           "chat-456",
			FinishReason: "COMPLETE",
			Message: cohereResponseMessage{
				Role:    "assistant",
				Content: []cohereContentBlock{{Type: "text", Text: "Hi!"}},
			},
			Usage: cohereUsage{
				BilledUnits: &cohereBilledUnits{InputTokens: 8, OutputTokens: 3},
			},
		})
	}))
	defer server.Close()

	p := NewCohere(server.Client())
	cfg := &ai.ProviderConfig{Name: "cohere", APIKey: "test-key", BaseURL: server.URL + "/v2"}

	resp, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model:    "command-r-plus",
		Messages: []ai.Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
	}, cfg)

	require.NoError(t, err)
	assert.Equal(t, 8, resp.Usage.PromptTokens)
	assert.Equal(t, 3, resp.Usage.CompletionTokens)
	assert.Equal(t, 11, resp.Usage.TotalTokens)
}

func TestCohere_FinishReasonMapping(t *testing.T) {
	tests := []struct {
		cohere string
		openai string
	}{
		{"COMPLETE", "stop"},
		{"MAX_TOKENS", "length"},
		{"TOOL_CALL", "tool_calls"},
		{"ERROR", "stop"},
		{"STOP_SEQUENCE", "stop"},
		{"unknown", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.cohere, func(t *testing.T) {
			assert.Equal(t, tt.openai, mapCohereFinishReason(tt.cohere))
		})
	}
}

func TestCohere_ToolUse(t *testing.T) {
	var receivedBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedBody)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cohereResponse{
			ID:           "chat-789",
			FinishReason: "TOOL_CALL",
			Message: cohereResponseMessage{
				Role: "assistant",
				ToolCalls: []cohereToolCall{{
					ID:   "tc_123",
					Type: "function",
					Function: cohereToolCallFunction{
						Name:      "get_weather",
						Arguments: `{"location":"NYC"}`,
					},
				}},
			},
			Usage: cohereUsage{
				Tokens: &cohereTokens{InputTokens: 20, OutputTokens: 15},
			},
		})
	}))
	defer server.Close()

	p := NewCohere(server.Client())
	cfg := &ai.ProviderConfig{Name: "cohere", APIKey: "test-key", BaseURL: server.URL + "/v2"}

	resp, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model:    "command-r-plus",
		Messages: []ai.Message{{Role: "user", Content: json.RawMessage(`"Weather in NYC?"`)}},
		Tools: []ai.Tool{{
			Type: "function",
			Function: ai.ToolFunction{
				Name:        "get_weather",
				Description: "Get weather",
				Parameters:  json.RawMessage(`{"type":"object","properties":{"location":{"type":"string"}}}`),
			},
		}},
	}, cfg)

	require.NoError(t, err)
	assert.Equal(t, "tool_calls", *resp.Choices[0].FinishReason)
	assert.Len(t, resp.Choices[0].Message.ToolCalls, 1)
	assert.Equal(t, "get_weather", resp.Choices[0].Message.ToolCalls[0].Function.Name)
	assert.Equal(t, "tc_123", resp.Choices[0].Message.ToolCalls[0].ID)

	// Verify tools were sent in Cohere format
	tools := receivedBody["tools"].([]any)
	assert.Len(t, tools, 1)
	tool := tools[0].(map[string]any)
	assert.Equal(t, "function", tool["type"])
	fn := tool["function"].(map[string]any)
	assert.Equal(t, "get_weather", fn["name"])
}

func TestCohere_Stream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)

		events := []string{
			`event: message-start` + "\n" + `data: {"type":"message-start","id":"msg_123","delta":{"message":{"role":"assistant"}}}`,
			`event: content-start` + "\n" + `data: {"type":"content-start","index":0}`,
			`event: content-delta` + "\n" + `data: {"type":"content-delta","index":0,"delta":{"message":{"content":{"text":"Hello"}}}}`,
			`event: content-delta` + "\n" + `data: {"type":"content-delta","index":0,"delta":{"message":{"content":{"text":" world"}}}}`,
			`event: content-end` + "\n" + `data: {"type":"content-end","index":0}`,
			`event: message-end` + "\n" + `data: {"type":"message-end","id":"msg_123","delta":{"finish_reason":"COMPLETE","usage":{"tokens":{"input_tokens":10,"output_tokens":5}}}}`,
		}
		for _, event := range events {
			w.Write([]byte(event + "\n\n"))
			flusher.Flush()
		}
	}))
	defer server.Close()

	p := NewCohere(server.Client())
	cfg := &ai.ProviderConfig{Name: "cohere", APIKey: "test-key", BaseURL: server.URL + "/v2"}

	stream, err := p.ChatCompletionStream(t.Context(), &ai.ChatCompletionRequest{
		Model:    "command-r-plus",
		Messages: []ai.Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
	}, cfg)
	require.NoError(t, err)
	defer stream.Close()

	// message-start -> role chunk
	chunk, err := stream.Read()
	require.NoError(t, err)
	assert.Equal(t, "assistant", chunk.Choices[0].Delta.Role)
	assert.Equal(t, "msg_123", chunk.ID)

	// content-start -> skipped
	// content-delta -> "Hello"
	chunk, err = stream.Read()
	require.NoError(t, err)
	assert.Equal(t, "Hello", *chunk.Choices[0].Delta.Content)

	// content-delta -> " world"
	chunk, err = stream.Read()
	require.NoError(t, err)
	assert.Equal(t, " world", *chunk.Choices[0].Delta.Content)

	// content-end -> skipped
	// message-end -> finish_reason + usage
	chunk, err = stream.Read()
	require.NoError(t, err)
	assert.Equal(t, "stop", *chunk.Choices[0].FinishReason)
	assert.Equal(t, 10, chunk.Usage.PromptTokens)
	assert.Equal(t, 5, chunk.Usage.CompletionTokens)

	// EOF after message-end
	_, err = stream.Read()
	assert.Equal(t, io.EOF, err)
}

func TestCohere_Embeddings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v2/embed", r.URL.Path)

		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		json.Unmarshal(body, &req)
		assert.Equal(t, "embed-english-v3.0", req["model"])
		assert.Equal(t, "search_document", req["input_type"])

		texts := req["texts"].([]any)
		assert.Len(t, texts, 1)
		assert.Equal(t, "hello", texts[0])

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cohereEmbeddingResponse{
			ID: "emb_123",
			Embeddings: cohereEmbeddingsData{
				Float: [][]float32{{0.1, 0.2, 0.3}},
			},
			Meta: &cohereEmbeddingMeta{
				BilledUnits: &cohereBilledUnits{InputTokens: 1},
			},
		})
	}))
	defer server.Close()

	p := NewCohere(server.Client())
	cfg := &ai.ProviderConfig{Name: "cohere", APIKey: "test-key", BaseURL: server.URL + "/v2"}

	resp, err := p.Embeddings(t.Context(), &ai.EmbeddingRequest{
		Input: "hello",
		Model: "embed-english-v3.0",
	}, cfg)

	require.NoError(t, err)
	assert.Equal(t, "list", resp.Object)
	assert.Len(t, resp.Data, 1)
	assert.Equal(t, []float32{0.1, 0.2, 0.3}, resp.Data[0].Embedding)
	assert.Equal(t, 0, resp.Data[0].Index)
	assert.Equal(t, 1, resp.Usage.PromptTokens)
}

func TestCohere_ListModels(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v2/models", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cohereModelsResponse{
			Models: []cohereModel{
				{Name: "command-r-plus"},
				{Name: "command-r"},
				{Name: "embed-english-v3.0"},
			},
		})
	}))
	defer server.Close()

	p := NewCohere(server.Client())
	cfg := &ai.ProviderConfig{Name: "cohere", APIKey: "test-key", BaseURL: server.URL + "/v2"}

	models, err := p.ListModels(t.Context(), cfg)
	require.NoError(t, err)
	assert.Len(t, models, 3)
	assert.Equal(t, "command-r-plus", models[0].ID)
	assert.Equal(t, "cohere", models[0].OwnedBy)
}

func TestCohere_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"message":"invalid model name"}`))
	}))
	defer server.Close()

	p := NewCohere(server.Client())
	cfg := &ai.ProviderConfig{Name: "cohere", APIKey: "test-key", BaseURL: server.URL + "/v2"}

	_, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model:    "bad-model",
		Messages: []ai.Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
	}, cfg)

	require.Error(t, err)
	aiErr, ok := err.(*ai.AIError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, aiErr.StatusCode)
	assert.Equal(t, "invalid model name", aiErr.Message)
}

func TestCohere_SupportsOperation(t *testing.T) {
	cfg := &ai.ProviderConfig{Name: "cohere", Type: "cohere"}

	assert.True(t, cfg.SupportsOperation(ai.OperationChatCompletions))
	assert.True(t, cfg.SupportsOperation(ai.OperationEmbeddings))
	assert.True(t, cfg.SupportsOperation(ai.OperationModels))
	assert.False(t, cfg.SupportsOperation(ai.OperationModerations))
	assert.False(t, cfg.SupportsOperation(ai.OperationBatches))
}
