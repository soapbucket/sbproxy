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

func TestAzure_ChatCompletion(t *testing.T) {
	finishReason := "stop"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify URL structure: /openai/deployments/{deployment}/chat/completions?api-version=X
		assert.Contains(t, r.URL.Path, "/openai/deployments/gpt4-deployment/chat/completions")
		assert.Equal(t, "2024-02-01", r.URL.Query().Get("api-version"))
		assert.Equal(t, "test-key", r.Header.Get("api-key"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Model should be empty in body (Azure uses deployment in URL)
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		json.Unmarshal(body, &req)
		assert.Equal(t, "", req["model"])

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ai.ChatCompletionResponse{
			ID: "chatcmpl-123", Object: "chat.completion", Model: "gpt-4",
			Choices: []ai.Choice{{Index: 0, FinishReason: &finishReason, Message: ai.Message{Role: "assistant", Content: json.RawMessage(`"Hello!"`)}}},
			Usage:   &ai.Usage{PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15},
		})
	}))
	defer server.Close()

	p := NewAzure(server.Client())
	cfg := &ai.ProviderConfig{
		Name:    "azure",
		APIKey:  "test-key",
		BaseURL: server.URL,
		DeploymentMap: map[string]string{
			"gpt-4": "gpt4-deployment",
		},
	}

	resp, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: []ai.Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
	}, cfg)

	require.NoError(t, err)
	assert.Equal(t, "chatcmpl-123", resp.ID)
	assert.Len(t, resp.Choices, 1)
}

func TestAzure_DeploymentMap(t *testing.T) {
	a := &Azure{}

	// With deployment map
	cfg := &ai.ProviderConfig{
		DeploymentMap: map[string]string{
			"gpt-4":         "gpt4-turbo-deployment",
			"gpt-3.5-turbo": "gpt35-deployment",
		},
	}
	assert.Equal(t, "gpt4-turbo-deployment", a.resolveDeployment("gpt-4", cfg))
	assert.Equal(t, "gpt35-deployment", a.resolveDeployment("gpt-3.5-turbo", cfg))
	assert.Equal(t, "unknown-model", a.resolveDeployment("unknown-model", cfg))

	// Without deployment map — falls back to model name
	cfg2 := &ai.ProviderConfig{}
	assert.Equal(t, "gpt-4", a.resolveDeployment("gpt-4", cfg2))
}

func TestAzure_CustomAPIVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "2024-08-01-preview", r.URL.Query().Get("api-version"))
		finishReason := "stop"
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ai.ChatCompletionResponse{
			ID: "chatcmpl-1", Object: "chat.completion", Model: "gpt-4",
			Choices: []ai.Choice{{FinishReason: &finishReason, Message: ai.Message{Role: "assistant", Content: json.RawMessage(`"Hi"`)}}},
		})
	}))
	defer server.Close()

	p := NewAzure(server.Client())
	cfg := &ai.ProviderConfig{
		Name:       "azure",
		APIKey:     "test-key",
		BaseURL:    server.URL,
		APIVersion: "2024-08-01-preview",
	}

	_, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: []ai.Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
	}, cfg)
	require.NoError(t, err)
}

func TestAzure_Stream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/chat/completions")

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)

		chunks := []string{
			`{"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}`,
			`{"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}`,
		}
		for _, chunk := range chunks {
			w.Write([]byte("data: " + chunk + "\n\n"))
			flusher.Flush()
		}
		w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	}))
	defer server.Close()

	p := NewAzure(server.Client())
	cfg := &ai.ProviderConfig{Name: "azure", APIKey: "test-key", BaseURL: server.URL}

	stream, err := p.ChatCompletionStream(t.Context(), &ai.ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: []ai.Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
	}, cfg)
	require.NoError(t, err)
	defer stream.Close()

	chunk, err := stream.Read()
	require.NoError(t, err)
	assert.Equal(t, "assistant", chunk.Choices[0].Delta.Role)

	chunk, err = stream.Read()
	require.NoError(t, err)
	assert.Equal(t, "Hello", *chunk.Choices[0].Delta.Content)

	_, err = stream.Read()
	assert.Equal(t, io.EOF, err)
}

func TestAzure_Embeddings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/openai/deployments/embed-deployment/embeddings")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ai.EmbeddingResponse{
			Object: "list",
			Data: []ai.EmbeddingData{{Object: "embedding", Embedding: []float32{0.1, 0.2}, Index: 0}},
			Model:  "text-embedding-3-small",
		})
	}))
	defer server.Close()

	p := NewAzure(server.Client())
	cfg := &ai.ProviderConfig{
		Name: "azure", APIKey: "test-key", BaseURL: server.URL,
		APIVersion:    "2024-02-01",
		DeploymentMap: map[string]string{"text-embedding-3-small": "embed-deployment"},
	}

	resp, err := p.Embeddings(t.Context(), &ai.EmbeddingRequest{
		Model: "text-embedding-3-small", Input: "Hello",
	}, cfg)
	require.NoError(t, err)
	assert.Len(t, resp.Data, 1)
}

func TestAzure_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ai.ErrorResponse{
			Error: ai.AIError{Type: "authentication_error", Message: "Invalid API key"},
		})
	}))
	defer server.Close()

	p := NewAzure(server.Client())
	cfg := &ai.ProviderConfig{Name: "azure", APIKey: "bad-key", BaseURL: server.URL}

	_, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: []ai.Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
	}, cfg)

	require.Error(t, err)
	aiErr, ok := err.(*ai.AIError)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, aiErr.StatusCode)
}
