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

func TestOpenAI_ChatCompletion(t *testing.T) {
	finishReason := "stop"
	expectedResp := ai.ChatCompletionResponse{
		ID:      "chatcmpl-123",
		Object:  "chat.completion",
		Created: 1700000000,
		Model:   "gpt-4",
		Choices: []ai.Choice{{
			Index:        0,
			Message:      ai.Message{Role: "assistant", Content: json.RawMessage(`"Hello!"`)},
			FinishReason: &finishReason,
		}},
		Usage: &ai.Usage{PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/chat/completions", r.URL.Path)
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Verify request body doesn't contain SB extensions
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		json.Unmarshal(body, &req)
		assert.NotContains(t, req, "sb_tags")
		assert.NotContains(t, req, "sb_cache_control")

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expectedResp)
	}))
	defer server.Close()

	p := NewOpenAI(server.Client())
	cfg := &ai.ProviderConfig{
		Name:   "openai",
		APIKey: "test-key",
		BaseURL: server.URL + "/v1",
	}

	resp, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model: "gpt-4",
		Messages: []ai.Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
		SBTags: map[string]string{"env": "test"},
	}, cfg)

	require.NoError(t, err)
	assert.Equal(t, "chatcmpl-123", resp.ID)
	assert.Equal(t, "gpt-4", resp.Model)
	assert.Len(t, resp.Choices, 1)
}

func TestOpenAI_ChatCompletion_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(ai.ErrorResponse{
			Error: ai.AIError{
				Type:    "rate_limit_error",
				Message: "Rate limit exceeded",
			},
		})
	}))
	defer server.Close()

	p := NewOpenAI(server.Client())
	cfg := &ai.ProviderConfig{
		Name:    "openai",
		APIKey:  "test-key",
		BaseURL: server.URL + "/v1",
	}

	_, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: []ai.Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
	}, cfg)

	require.Error(t, err)
	aiErr, ok := err.(*ai.AIError)
	require.True(t, ok)
	assert.Equal(t, http.StatusTooManyRequests, aiErr.StatusCode)
	assert.Contains(t, aiErr.Message, "Rate limit")
}

func TestOpenAI_ChatCompletionStream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/chat/completions", r.URL.Path)

		// Verify stream is set in request
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		json.Unmarshal(body, &req)
		assert.Equal(t, true, req["stream"])

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)

		chunks := []string{
			`{"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}`,
			`{"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}`,
			`{"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
		}
		for _, chunk := range chunks {
			w.Write([]byte("data: " + chunk + "\n\n"))
			flusher.Flush()
		}
		w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	}))
	defer server.Close()

	p := NewOpenAI(server.Client())
	cfg := &ai.ProviderConfig{
		Name:    "openai",
		APIKey:  "test-key",
		BaseURL: server.URL + "/v1",
	}

	stream, err := p.ChatCompletionStream(t.Context(), &ai.ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: []ai.Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
	}, cfg)
	require.NoError(t, err)
	defer stream.Close()

	// Read first chunk (role)
	chunk, err := stream.Read()
	require.NoError(t, err)
	assert.Equal(t, "assistant", chunk.Choices[0].Delta.Role)

	// Read second chunk (content)
	chunk, err = stream.Read()
	require.NoError(t, err)
	assert.Equal(t, "Hello", *chunk.Choices[0].Delta.Content)

	// Read third chunk (finish)
	chunk, err = stream.Read()
	require.NoError(t, err)
	assert.Equal(t, "stop", *chunk.Choices[0].FinishReason)

	// Read EOF
	_, err = stream.Read()
	assert.Equal(t, io.EOF, err)
}

func TestOpenAI_Embeddings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/embeddings", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ai.EmbeddingResponse{
			Object: "list",
			Data: []ai.EmbeddingData{{
				Object:    "embedding",
				Embedding: []float32{0.1, 0.2, 0.3},
				Index:     0,
			}},
			Model: "text-embedding-3-small",
		})
	}))
	defer server.Close()

	p := NewOpenAI(server.Client())
	cfg := &ai.ProviderConfig{
		Name:    "openai",
		APIKey:  "test-key",
		BaseURL: server.URL + "/v1",
	}

	resp, err := p.Embeddings(t.Context(), &ai.EmbeddingRequest{
		Model: "text-embedding-3-small",
		Input: "Hello",
	}, cfg)
	require.NoError(t, err)
	assert.Len(t, resp.Data, 1)
	assert.Len(t, resp.Data[0].Embedding, 3)
}

func TestOpenAI_ListModels(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/models", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ai.ModelListResponse{
			Object: "list",
			Data: []ai.ModelInfo{
				{ID: "gpt-4", Object: "model", OwnedBy: "openai"},
			},
		})
	}))
	defer server.Close()

	p := NewOpenAI(server.Client())
	cfg := &ai.ProviderConfig{
		Name:    "openai",
		BaseURL: server.URL + "/v1",
	}

	models, err := p.ListModels(t.Context(), cfg)
	require.NoError(t, err)
	assert.Len(t, models, 1)
	assert.Equal(t, "gpt-4", models[0].ID)
}

func TestOpenAI_Headers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))
		assert.Equal(t, "org-123", r.Header.Get("OpenAI-Organization"))
		assert.Equal(t, "proj-456", r.Header.Get("OpenAI-Project"))
		assert.Equal(t, "custom-value", r.Header.Get("X-Custom"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ai.ModelListResponse{Object: "list"})
	}))
	defer server.Close()

	p := NewOpenAI(server.Client())
	cfg := &ai.ProviderConfig{
		Name:         "openai",
		APIKey:       "test-key",
		BaseURL:      server.URL + "/v1",
		Organization: "org-123",
		ProjectID:    "proj-456",
		Headers:      map[string]string{"X-Custom": "custom-value"},
	}

	_, err := p.ListModels(t.Context(), cfg)
	require.NoError(t, err)
}

func TestOpenAI_ModelMap(t *testing.T) {
	var receivedModel string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		json.Unmarshal(body, &req)
		receivedModel = req["model"].(string)

		finishReason := "stop"
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ai.ChatCompletionResponse{
			ID: "chatcmpl-123", Object: "chat.completion", Model: receivedModel,
			Choices: []ai.Choice{{FinishReason: &finishReason, Message: ai.Message{Role: "assistant", Content: json.RawMessage(`"Hi"`)}}},
		})
	}))
	defer server.Close()

	p := NewOpenAI(server.Client())
	cfg := &ai.ProviderConfig{
		Name:     "openai",
		APIKey:   "test-key",
		BaseURL:  server.URL + "/v1",
		ModelMap: map[string]string{"my-model": "gpt-4-turbo"},
	}

	_, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model:    "my-model",
		Messages: []ai.Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
	}, cfg)
	require.NoError(t, err)
	assert.Equal(t, "gpt-4-turbo", receivedModel)
}
