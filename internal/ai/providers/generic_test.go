package providers

import (
	json "github.com/goccy/go-json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneric_Name(t *testing.T) {
	p := NewGeneric(http.DefaultClient)
	assert.Equal(t, "generic", p.Name())
}

func TestGeneric_ChatCompletion_CustomBaseURL(t *testing.T) {
	finishReason := "stop"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/chat/completions", r.URL.Path)
		assert.Equal(t, "Bearer custom-key", r.Header.Get("Authorization"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ai.ChatCompletionResponse{
			ID: "cmpl-123", Object: "chat.completion", Model: "local-model",
			Choices: []ai.Choice{{
				Index: 0, FinishReason: &finishReason,
				Message: ai.Message{Role: "assistant", Content: json.RawMessage(`"Hello from custom provider!"`)},
			}},
		})
	}))
	defer server.Close()

	p := NewGeneric(server.Client())
	cfg := &ai.ProviderConfig{
		Name:    "custom-llm",
		Type:    "generic",
		APIKey:  "custom-key",
		BaseURL: server.URL + "/v1",
	}

	resp, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model:    "local-model",
		Messages: []ai.Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
	}, cfg)

	require.NoError(t, err)
	assert.Equal(t, "cmpl-123", resp.ID)
	assert.Equal(t, "local-model", resp.Model)
}

func TestGeneric_Streaming(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)

		w.Write([]byte(`data: {"id":"cmpl-1","object":"chat.completion.chunk","model":"local","choices":[{"index":0,"delta":{"content":"Hi"},"finish_reason":null}]}` + "\n\n"))
		w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	}))
	defer server.Close()

	p := NewGeneric(server.Client())
	cfg := &ai.ProviderConfig{
		Name:    "custom",
		Type:    "generic",
		BaseURL: server.URL + "/v1",
	}

	stream, err := p.ChatCompletionStream(t.Context(), &ai.ChatCompletionRequest{
		Model:    "local",
		Messages: []ai.Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
	}, cfg)
	require.NoError(t, err)
	defer stream.Close()

	chunk, err := stream.Read()
	require.NoError(t, err)
	assert.Equal(t, "Hi", *chunk.Choices[0].Delta.Content)
}

func TestGeneric_SupportsAllCapabilities(t *testing.T) {
	p := NewGeneric(http.DefaultClient)
	assert.True(t, p.SupportsStreaming())
	assert.True(t, p.SupportsEmbeddings())
}

func TestGenericPassthrough(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Token test-key", r.Header.Get("X-Custom-Auth"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id":    "resp-1",
			"model": "custom-model",
			"choices": []map[string]any{
				{"index": 0, "message": map[string]any{"role": "assistant", "content": "hello"}},
			},
			"usage": map[string]any{
				"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15,
			},
		})
	}))
	defer server.Close()

	p := NewGeneric(server.Client())
	cfg := &ai.ProviderConfig{
		Name:       "custom",
		Type:       "generic",
		BaseURL:    server.URL,
		APIKey:     "test-key",
		Format:     "passthrough",
		AuthHeader: "X-Custom-Auth",
		AuthPrefix: "Token",
	}

	resp, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model:    "custom-model",
		Messages: []ai.Message{{Role: "user", Content: json.RawMessage(`"hi"`)}},
	}, cfg)
	require.NoError(t, err)
	assert.Equal(t, "custom-model", resp.Model)
	assert.Len(t, resp.Choices, 1)
}

func TestGenericOpenAICompatible(t *testing.T) {
	p := NewGeneric(http.DefaultClient)
	assert.Equal(t, "generic", p.Name())
	assert.True(t, p.SupportsStreaming())
}

func TestGenericSetAuthHeader(t *testing.T) {
	g := &Generic{}

	tests := []struct {
		name       string
		cfg        *ai.ProviderConfig
		wantHeader string
		wantValue  string
	}{
		{
			name:       "default bearer",
			cfg:        &ai.ProviderConfig{APIKey: "key123"},
			wantHeader: "Authorization",
			wantValue:  "Bearer key123",
		},
		{
			name:       "custom header and prefix",
			cfg:        &ai.ProviderConfig{APIKey: "key123", AuthHeader: "X-Api-Key", AuthPrefix: ""},
			wantHeader: "X-Api-Key",
			wantValue:  "key123",
		},
		{
			name:       "no key",
			cfg:        &ai.ProviderConfig{},
			wantHeader: "",
			wantValue:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://example.com", nil)
			g.setAuthHeader(req, tt.cfg)
			if tt.wantHeader != "" {
				assert.Equal(t, tt.wantValue, req.Header.Get(tt.wantHeader))
			}
		})
	}
}
