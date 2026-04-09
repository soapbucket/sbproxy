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

func TestMistralProvider(t *testing.T) {
	cfg := &ai.ProviderConfig{Name: "mistral", Type: "mistral"}
	p, err := ai.NewProvider(cfg, http.DefaultClient)
	require.NoError(t, err, "failed to create mistral provider")

	assert.Equal(t, "mistral", p.Name())
	assert.True(t, p.SupportsStreaming(), "expected streaming support")
	assert.True(t, p.SupportsEmbeddings(), "expected embeddings support")
}

func TestMistral_ChatCompletion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/chat/completions", r.URL.Path)
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))

		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		json.Unmarshal(body, &req)
		assert.Equal(t, "mistral-large-latest", req["model"])

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ai.ChatCompletionResponse{
			ID:      "chat-123",
			Object:  "chat.completion",
			Model:   "mistral-large-latest",
			Choices: []ai.Choice{{Index: 0, Message: ai.Message{Role: "assistant", Content: json.RawMessage(`"Hello!"`)}, FinishReason: strPtr("stop")}},
			Usage:   &ai.Usage{PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15},
		})
	}))
	defer server.Close()

	p := NewMistral(server.Client())
	cfg := &ai.ProviderConfig{
		Name:    "mistral",
		APIKey:  "test-key",
		BaseURL: server.URL + "/v1",
	}

	resp, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model:    "mistral-large-latest",
		Messages: []ai.Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
	}, cfg)

	require.NoError(t, err)
	assert.Equal(t, "chat-123", resp.ID)
	assert.Equal(t, "chat.completion", resp.Object)
	assert.Len(t, resp.Choices, 1)
	assert.Equal(t, "stop", *resp.Choices[0].FinishReason)
	assert.Equal(t, 10, resp.Usage.PromptTokens)
	assert.Equal(t, 5, resp.Usage.CompletionTokens)
}

func TestMistral_Stream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)

		events := []string{
			`data: {"id":"chat-123","object":"chat.completion.chunk","model":"mistral-large-latest","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}`,
			`data: {"id":"chat-123","object":"chat.completion.chunk","model":"mistral-large-latest","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}`,
			`data: {"id":"chat-123","object":"chat.completion.chunk","model":"mistral-large-latest","choices":[{"index":0,"delta":{"content":" world"},"finish_reason":null}]}`,
			`data: {"id":"chat-123","object":"chat.completion.chunk","model":"mistral-large-latest","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`,
			`data: [DONE]`,
		}
		for _, event := range events {
			w.Write([]byte(event + "\n\n"))
			flusher.Flush()
		}
	}))
	defer server.Close()

	p := NewMistral(server.Client())
	cfg := &ai.ProviderConfig{Name: "mistral", APIKey: "test-key", BaseURL: server.URL + "/v1"}

	stream, err := p.ChatCompletionStream(t.Context(), &ai.ChatCompletionRequest{
		Model:    "mistral-large-latest",
		Messages: []ai.Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
	}, cfg)
	require.NoError(t, err)
	defer stream.Close()

	// Role chunk
	chunk, err := stream.Read()
	require.NoError(t, err)
	assert.Equal(t, "assistant", chunk.Choices[0].Delta.Role)

	// "Hello"
	chunk, err = stream.Read()
	require.NoError(t, err)
	assert.Equal(t, "Hello", *chunk.Choices[0].Delta.Content)

	// " world"
	chunk, err = stream.Read()
	require.NoError(t, err)
	assert.Equal(t, " world", *chunk.Choices[0].Delta.Content)

	// finish
	chunk, err = stream.Read()
	require.NoError(t, err)
	assert.Equal(t, "stop", *chunk.Choices[0].FinishReason)

	// EOF
	_, err = stream.Read()
	assert.Equal(t, io.EOF, err)
}

func strPtr(s string) *string { return &s }
