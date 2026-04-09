package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/pricing"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockGuardrailRunner struct {
	results []GuardrailCheckResult
	err     error
	outputBlock *GuardrailBlock
	outputErr   error
}

func (m *mockGuardrailRunner) CheckInput(_ context.Context, messages []Message, _ string) ([]Message, *GuardrailBlock, error) {
	return messages, nil, nil
}

func (m *mockGuardrailRunner) CheckOutput(_ context.Context, messages []Message, _ string) ([]Message, *GuardrailBlock, error) {
	if m.outputErr != nil {
		return messages, nil, m.outputErr
	}
	return messages, m.outputBlock, nil
}

func (m *mockGuardrailRunner) HasInput() bool  { return true }
func (m *mockGuardrailRunner) HasOutput() bool { return true }

func (m *mockGuardrailRunner) CheckContent(_ context.Context, _ string, _ string, _ string, _ []string) ([]GuardrailCheckResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.results, nil
}

// mockProvider implements Provider for handler tests.
type mockProvider struct {
	name         string
	lastChatReq  *ChatCompletionRequest
	chatResp     *ChatCompletionResponse
	chatErr      error
	streamChunks []*StreamChunk
	streamErr    error
	embedResp    *EmbeddingResponse
	embedErr     error
	models       []ModelInfo
}

var _ Provider = (*mockProvider)(nil)

func (m *mockProvider) Name() string { return m.name }
func (m *mockProvider) ChatCompletion(_ context.Context, req *ChatCompletionRequest, _ *ProviderConfig) (*ChatCompletionResponse, error) {
	m.lastChatReq = req
	return m.chatResp, m.chatErr
}
func (m *mockProvider) ChatCompletionStream(_ context.Context, _ *ChatCompletionRequest, _ *ProviderConfig) (StreamReader, error) {
	if m.streamErr != nil {
		return nil, m.streamErr
	}
	return &mockStreamReader{chunks: m.streamChunks}, nil
}
func (m *mockProvider) Embeddings(_ context.Context, _ *EmbeddingRequest, _ *ProviderConfig) (*EmbeddingResponse, error) {
	return m.embedResp, m.embedErr
}
func (m *mockProvider) ListModels(_ context.Context, _ *ProviderConfig) ([]ModelInfo, error) {
	return m.models, nil
}
func (m *mockProvider) SupportsStreaming() bool  { return true }
func (m *mockProvider) SupportsEmbeddings() bool { return true }

type mockStreamReader struct {
	chunks []*StreamChunk
	idx    int
}

func (r *mockStreamReader) Read() (*StreamChunk, error) {
	if r.idx >= len(r.chunks) {
		return nil, io.EOF
	}
	chunk := r.chunks[r.idx]
	r.idx++
	return chunk, nil
}

func (r *mockStreamReader) Close() error { return nil }

func newTestHandler(t *testing.T, mp *mockProvider, cfg *ProviderConfig) *Handler {
	t.Helper()
	providers := []*ProviderConfig{cfg}
	h := &Handler{
		config: &HandlerConfig{
			Providers:          providers,
			MaxRequestBodySize: 10 * 1024 * 1024,
		},
		providers: map[string]providerEntry{
			cfg.Name: {provider: mp, config: cfg},
		},
		router: NewRouter(nil, providers),
	}
	return h
}

func TestHandler_ChatCompletion_NonStreaming(t *testing.T) {
	finishReason := "stop"
	mp := &mockProvider{
		name: "test",
		chatResp: &ChatCompletionResponse{
			ID:      "chatcmpl-123",
			Object:  "chat.completion",
			Created: 1700000000,
			Model:   "gpt-4",
			Choices: []Choice{{
				Index:        0,
				Message:      Message{Role: "assistant", Content: json.RawMessage(`"Hello!"`)},
				FinishReason: &finishReason,
			}},
		},
	}

	cfg := &ProviderConfig{Name: "test"}
	h := newTestHandler(t, mp, cfg)

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var resp ChatCompletionResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "chatcmpl-123", resp.ID)
	assert.Len(t, resp.Choices, 1)
}

func TestHandler_ChatCompletion_Streaming(t *testing.T) {
	text := "Hello"
	finishReason := "stop"
	mp := &mockProvider{
		name: "test",
		streamChunks: []*StreamChunk{
			{
				ID:     "chatcmpl-1",
				Object: "chat.completion.chunk",
				Model:  "gpt-4",
				Choices: []StreamChoice{{
					Index: 0,
					Delta: StreamDelta{Role: "assistant"},
				}},
			},
			{
				ID:     "chatcmpl-1",
				Object: "chat.completion.chunk",
				Model:  "gpt-4",
				Choices: []StreamChoice{{
					Index: 0,
					Delta: StreamDelta{Content: &text},
				}},
			},
			{
				ID:     "chatcmpl-1",
				Object: "chat.completion.chunk",
				Model:  "gpt-4",
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

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}],"stream":true}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/event-stream", w.Header().Get("Content-Type"))

	body := w.Body.String()
	assert.Contains(t, body, "data: ")
	assert.Contains(t, body, "data: [DONE]")
	assert.Contains(t, body, "chatcmpl-1")
}

func TestHandler_ChatCompletion_StreamingBufferedGuardrailBlocks(t *testing.T) {
	text := "blocked content"
	finishReason := "stop"
	mp := &mockProvider{
		name: "test",
		streamChunks: []*StreamChunk{
			{
				ID:    "chatcmpl-1",
				Model: "gpt-4",
				Choices: []StreamChoice{{
					Index: 0,
					Delta: StreamDelta{Content: &text},
				}},
			},
			{
				ID:    "chatcmpl-1",
				Model: "gpt-4",
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
	h.config.Guardrails = &mockGuardrailRunner{
		outputBlock: &GuardrailBlock{Name: "toxicity", Reason: "unsafe"},
	}
	h.config.StreamingGuardrailMode = "buffered_response_scan"

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}],"stream":true}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "guardrail_blocked")
	assert.NotContains(t, w.Body.String(), "data: [DONE]")
}

func TestHandler_ChatCompletion_StreamingBestEffortGuardrailBlocks(t *testing.T) {
	text := strings.Repeat("x", 300)
	finishReason := "stop"
	mp := &mockProvider{
		name: "test",
		streamChunks: []*StreamChunk{
			{
				ID:    "chatcmpl-1",
				Model: "gpt-4",
				Choices: []StreamChoice{{
					Index: 0,
					Delta: StreamDelta{Content: &text},
				}},
			},
			{
				ID:    "chatcmpl-1",
				Model: "gpt-4",
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
	h.config.Guardrails = &mockGuardrailRunner{
		outputBlock: &GuardrailBlock{Name: "policy", Reason: "blocked"},
	}
	h.config.StreamingGuardrailMode = "best_effort_chunk_scan"

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}],"stream":true}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "guardrail_blocked")
	assert.NotContains(t, w.Body.String(), "data: [DONE]")
}

func TestHandler_ChatCompletion_MissingModel(t *testing.T) {
	mp := &mockProvider{name: "test"}
	cfg := &ProviderConfig{Name: "test"}
	h := newTestHandler(t, mp, cfg)

	reqBody := `{"messages":[{"role":"user","content":"Hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(reqBody))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "model is required")
}

func TestHandler_ChatCompletion_DefaultModel(t *testing.T) {
	finishReason := "stop"
	mp := &mockProvider{
		name: "test",
		chatResp: &ChatCompletionResponse{
			ID:      "chatcmpl-123",
			Object:  "chat.completion",
			Model:   "gpt-4",
			Choices: []Choice{{FinishReason: &finishReason, Message: Message{Role: "assistant", Content: json.RawMessage(`"Hi"`)}}},
		},
	}

	cfg := &ProviderConfig{Name: "test"}
	h := newTestHandler(t, mp, cfg)
	h.config.DefaultModel = "gpt-4"

	reqBody := `{"messages":[{"role":"user","content":"Hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(reqBody))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandler_ChatCompletion_PromptResolution(t *testing.T) {
	finishReason := "stop"
	mp := &mockProvider{
		name: "test",
		chatResp: &ChatCompletionResponse{
			ID:      "chatcmpl-123",
			Object:  "chat.completion",
			Model:   "gpt-4o",
			Choices: []Choice{{FinishReason: &finishReason, Message: Message{Role: "assistant", Content: json.RawMessage(`"Hi"`)}}},
		},
	}
	cfg := &ProviderConfig{Name: "test", Models: []string{"gpt-4o"}}
	h := newTestHandler(t, mp, cfg)

	promptServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "secret", r.Header.Get("X-Callback-Secret"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"rendered":"Rendered user prompt",
			"system_prompt":"System prompt",
			"model":"gpt-4o",
			"version_number":7
		}`))
	}))
	defer promptServer.Close()
	h.client = promptServer.Client()
	h.config.PromptRegistryURL = promptServer.URL

	reqBody := `{"prompt_id":"123e4567-e89b-12d3-a456-426614174000","prompt_variables":{"name":"rick"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rd := reqctx.NewRequestData()
	rd.Config["workspace_id"] = "ws-1"
	rd.Secrets["CALLBACK_SECRET"] = "secret"
	req = req.WithContext(reqctx.SetRequestData(req.Context(), rd))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, mp.lastChatReq)
	assert.Equal(t, "gpt-4o", mp.lastChatReq.Model)
	require.Len(t, mp.lastChatReq.Messages, 2)
	assert.Equal(t, "system", mp.lastChatReq.Messages[0].Role)
	assert.Contains(t, string(mp.lastChatReq.Messages[1].Content), "Rendered user prompt")
	assert.Equal(t, "123e4567-e89b-12d3-a456-426614174000", rd.DebugHeaders["X-Sb-Prompt-Id"])
	assert.Equal(t, "7", rd.DebugHeaders["X-Sb-Prompt-Version"])
}

func TestProviderExclusions_FromEntitlements(t *testing.T) {
	h := &Handler{
		config: &HandlerConfig{
			AllowedProviders: []string{"openai", "azure"},
		},
		providers: map[string]providerEntry{
			"openai":    {},
			"azure":     {},
			"anthropic": {},
		},
	}
	rd := reqctx.NewRequestData()
	rd.SessionData = &reqctx.SessionData{
			AuthData: &reqctx.AuthData{
				Data: map[string]any{
					"ai_entitlements": map[string]any{
						"allowed_providers": []any{"openai"},
						"blocked_providers": []any{"azure"},
					},
				},
			},
	}
	ctx := reqctx.SetRequestData(context.Background(), rd)

	exclude := h.providerExclusions(ctx)
	assert.True(t, exclude["azure"])
	assert.True(t, exclude["anthropic"])
	assert.False(t, exclude["openai"])
}

func TestProviderExclusions_FromProviderPolicy(t *testing.T) {
	h := &Handler{
		config: &HandlerConfig{
			ProviderPolicy: map[string]any{
				"allowed_regions": []any{"us-east-1"},
			},
		},
		providers: map[string]providerEntry{
			"openai-east": {config: &ProviderConfig{Name: "openai-east", Type: "openai", Region: "us-east-1"}},
			"openai-west": {config: &ProviderConfig{Name: "openai-west", Type: "openai", Region: "us-west-2"}},
		},
	}
	exclude := h.providerExclusions(context.Background())
	assert.False(t, exclude["openai-east"])
	assert.True(t, exclude["openai-west"])
}

func TestEffectivePrivacyMode(t *testing.T) {
	h := &Handler{config: &HandlerConfig{LogPolicy: "metadata_only"}}
	rd := reqctx.NewRequestData()
	rd.SessionData = &reqctx.SessionData{
		AuthData: &reqctx.AuthData{
			Data: map[string]any{
				"ai_entitlements": map[string]any{
					"privacy_mode": "zero_retention",
				},
			},
		},
	}
	ctx := reqctx.SetRequestData(context.Background(), rd)
	assert.Equal(t, "zero_retention", h.effectivePrivacyMode(ctx))
}

func TestHandler_Responses_NonStreamingPassthrough(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/responses", r.URL.Path)
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))

		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		require.NoError(t, json.Unmarshal(body, &req))
		assert.NotContains(t, req, "sb_tags")

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"resp_123",
			"object":"response",
			"model":"gpt-4o",
			"output":[{"type":"message","content":[{"type":"output_text","text":"Hello from responses"}]}],
			"usage":{"input_tokens":10,"output_tokens":5,"total_tokens":15}
		}`))
	}))
	defer server.Close()

	cfg := &ProviderConfig{
		Name:    "openai",
		Type:    "openai",
		APIKey:  "test-key",
		BaseURL: server.URL + "/v1",
		Models:  []string{"gpt-4o"},
	}
	h := &Handler{
		config: &HandlerConfig{
			Providers:          []*ProviderConfig{cfg},
			MaxRequestBodySize: 10 * 1024 * 1024,
		},
		providers: map[string]providerEntry{
			cfg.Name: {provider: &mockProvider{name: cfg.Name}, config: cfg},
		},
		router: NewRouter(nil, []*ProviderConfig{cfg}),
		client: server.Client(),
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewBufferString(`{
		"model":"gpt-4o",
		"input":"hello",
		"sb_tags":{"agent":"test-agent"}
	}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"id":"resp_123"`)
	assert.Contains(t, w.Body.String(), `"response"`)
}

func TestHandler_Responses_StreamingPassthrough(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/responses", r.URL.Path)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)

		events := []string{
			"event: response.created\ndata: {\"type\":\"response.created\"}\n\n",
			"event: response.output_text.delta\ndata: {\"delta\":\"Hello\"}\n\n",
			"event: response.completed\ndata: {\"response\":{\"usage\":{\"input_tokens\":8,\"output_tokens\":3,\"total_tokens\":11}}}\n\n",
		}
		for _, evt := range events {
			_, _ = w.Write([]byte(evt))
			flusher.Flush()
		}
	}))
	defer server.Close()

	cfg := &ProviderConfig{
		Name:    "openai",
		Type:    "openai",
		APIKey:  "test-key",
		BaseURL: server.URL + "/v1",
		Models:  []string{"gpt-4o"},
	}
	h := &Handler{
		config: &HandlerConfig{
			Providers:          []*ProviderConfig{cfg},
			MaxRequestBodySize: 10 * 1024 * 1024,
		},
		providers: map[string]providerEntry{
			cfg.Name: {provider: &mockProvider{name: cfg.Name}, config: cfg},
		},
		router: NewRouter(nil, []*ProviderConfig{cfg}),
		client: server.Client(),
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewBufferString(`{
		"model":"gpt-4o",
		"input":"hello",
		"stream":true
	}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/event-stream", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), "event: response.output_text.delta")
	assert.Contains(t, w.Body.String(), "\"delta\":\"Hello\"")
	assert.Contains(t, w.Body.String(), "event: response.completed")
}

func TestHandler_Responses_StreamingPassthrough_BufferedGuardrailBlocks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		events := []string{
			"event: response.output_text.delta\ndata: {\"delta\":\"unsafe output\"}\n\n",
			"event: response.completed\ndata: {\"response\":{\"usage\":{\"input_tokens\":8,\"output_tokens\":3,\"total_tokens\":11}}}\n\n",
			"data: [DONE]\n\n",
		}
		for _, evt := range events {
			_, _ = w.Write([]byte(evt))
			flusher.Flush()
		}
	}))
	defer server.Close()

	cfg := &ProviderConfig{Name: "openai", Type: "openai", APIKey: "test-key", BaseURL: server.URL + "/v1", Models: []string{"gpt-4o"}}
	h := &Handler{
		config: &HandlerConfig{
			Providers:              []*ProviderConfig{cfg},
			MaxRequestBodySize:     10 * 1024 * 1024,
			StreamingGuardrailMode: "buffered_response_scan",
			Guardrails:             &mockGuardrailRunner{outputBlock: &GuardrailBlock{Name: "policy", Reason: "blocked"}},
		},
		providers: map[string]providerEntry{
			cfg.Name: {provider: &mockProvider{name: cfg.Name}, config: cfg},
		},
		router: NewRouter(nil, []*ProviderConfig{cfg}),
		client: server.Client(),
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewBufferString(`{"model":"gpt-4o","input":"hello","stream":true}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "guardrail_blocked")
	assert.NotContains(t, w.Body.String(), "[DONE]")
}

func TestHandler_Responses_StreamingPassthrough_BestEffortGuardrailBlocks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		events := []string{
			"event: response.output_text.delta\ndata: {\"delta\":\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}\n\n",
			"event: response.completed\ndata: {\"response\":{\"usage\":{\"input_tokens\":8,\"output_tokens\":3,\"total_tokens\":11}}}\n\n",
			"data: [DONE]\n\n",
		}
		for _, evt := range events {
			_, _ = w.Write([]byte(evt))
			flusher.Flush()
		}
	}))
	defer server.Close()

	cfg := &ProviderConfig{Name: "openai", Type: "openai", APIKey: "test-key", BaseURL: server.URL + "/v1", Models: []string{"gpt-4o"}}
	h := &Handler{
		config: &HandlerConfig{
			Providers:              []*ProviderConfig{cfg},
			MaxRequestBodySize:     10 * 1024 * 1024,
			StreamingGuardrailMode: "best_effort_chunk_scan",
			Guardrails:             &mockGuardrailRunner{outputBlock: &GuardrailBlock{Name: "policy", Reason: "blocked"}},
		},
		providers: map[string]providerEntry{
			cfg.Name: {provider: &mockProvider{name: cfg.Name}, config: cfg},
		},
		router: NewRouter(nil, []*ProviderConfig{cfg}),
		client: server.Client(),
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewBufferString(`{"model":"gpt-4o","input":"hello","stream":true}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "guardrail_blocked")
	assert.NotContains(t, w.Body.String(), "data: [DONE]")
}

func TestHandler_FilesLifecyclePassthrough(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/files":
			if r.Method != http.MethodGet {
				t.Fatalf("expected GET for files list, got %s", r.Method)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"file_123","object":"file"}]}`))
		case "/v1/files/file_123":
			if r.Method != http.MethodDelete {
				t.Fatalf("expected DELETE for file delete, got %s", r.Method)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"file_123","object":"file","deleted":true}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &ProviderConfig{
		Name:    "openai",
		Type:    "openai",
		APIKey:  "test-key",
		BaseURL: server.URL + "/v1",
		Models:  []string{"gpt-4o"},
	}
	h := &Handler{
		config: &HandlerConfig{Providers: []*ProviderConfig{cfg}, MaxRequestBodySize: 10 * 1024 * 1024},
		providers: map[string]providerEntry{
			cfg.Name: {provider: &mockProvider{name: cfg.Name}, config: cfg},
		},
		router: NewRouter(nil, []*ProviderConfig{cfg}),
		client: server.Client(),
	}

	listReq := httptest.NewRequest(http.MethodGet, "/v1/files", nil)
	listW := httptest.NewRecorder()
	h.ServeHTTP(listW, listReq)
	assert.Equal(t, http.StatusOK, listW.Code)
	assert.Contains(t, listW.Body.String(), `"object":"list"`)

	deleteReq := httptest.NewRequest(http.MethodDelete, "/v1/files/file_123", nil)
	deleteW := httptest.NewRecorder()
	h.ServeHTTP(deleteW, deleteReq)
	assert.Equal(t, http.StatusOK, deleteW.Code)
	assert.Contains(t, deleteW.Body.String(), `"deleted":true`)
}

func TestHandler_BatchCancelPassthrough(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/batches/batch_123/cancel", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"batch_123","object":"batch","status":"cancelling"}`))
	}))
	defer server.Close()

	cfg := &ProviderConfig{
		Name:    "openai",
		Type:    "openai",
		APIKey:  "test-key",
		BaseURL: server.URL + "/v1",
		Models:  []string{"gpt-4o"},
	}
	h := &Handler{
		config: &HandlerConfig{Providers: []*ProviderConfig{cfg}, MaxRequestBodySize: 10 * 1024 * 1024},
		providers: map[string]providerEntry{
			cfg.Name: {provider: &mockProvider{name: cfg.Name}, config: cfg},
		},
		router: NewRouter(nil, []*ProviderConfig{cfg}),
		client: server.Client(),
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/batches/batch_123/cancel", bytes.NewBufferString(`{"input_file_id":"file_123","endpoint":"/v1/responses","completion_window":"24h"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"status":"cancelling"`)
}

func TestHandler_UnsupportedOperationReturnsInvalidRequest(t *testing.T) {
	cfg := &ProviderConfig{
		Name:   "anthropic",
		Type:   "anthropic",
		APIKey: "test-key",
		Models: []string{"claude-sonnet-4-20250514"},
	}
	h := &Handler{
		config: &HandlerConfig{Providers: []*ProviderConfig{cfg}, MaxRequestBodySize: 10 * 1024 * 1024},
		providers: map[string]providerEntry{
			cfg.Name: {provider: &mockProvider{name: cfg.Name}, config: cfg},
		},
		router: NewRouter(nil, []*ProviderConfig{cfg}),
		client: http.DefaultClient,
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/files", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "not supported")
}

func TestHandler_ChatCompletion_ProviderError(t *testing.T) {
	// Use a non-retryable error (401) so it's returned directly
	mp := &mockProvider{
		name:    "test",
		chatErr: &AIError{StatusCode: 401, Type: "authentication_error", Message: "invalid api key"},
	}

	cfg := &ProviderConfig{Name: "test"}
	h := newTestHandler(t, mp, cfg)

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(reqBody))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid api key")
}

func TestHandler_ChatCompletion_RetryExhausted(t *testing.T) {
	// Retryable error (429) with only one provider exhausts retries
	mp := &mockProvider{
		name:    "test",
		chatErr: ErrRateLimited("too many requests"),
	}

	cfg := &ProviderConfig{Name: "test"}
	h := newTestHandler(t, mp, cfg)

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(reqBody))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	// With retries exhausted on a single provider, should get "all providers unavailable"
	assert.Equal(t, http.StatusBadGateway, w.Code)
}

func TestHandler_ChatCompletion_GenericError(t *testing.T) {
	mp := &mockProvider{
		name:    "test",
		chatErr: fmt.Errorf("connection refused"),
	}

	cfg := &ProviderConfig{Name: "test"}
	h := newTestHandler(t, mp, cfg)

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(reqBody))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestHandler_ChatCompletion_InvalidMethod(t *testing.T) {
	mp := &mockProvider{name: "test"}
	cfg := &ProviderConfig{Name: "test"}
	h := newTestHandler(t, mp, cfg)

	req := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandler_ChatCompletion_InvalidBody(t *testing.T) {
	mp := &mockProvider{name: "test"}
	cfg := &ProviderConfig{Name: "test"}
	h := newTestHandler(t, mp, cfg)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString("not json"))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandler_ListModels(t *testing.T) {
	mp := &mockProvider{
		name: "test",
		models: []ModelInfo{
			{ID: "gpt-4", Object: "model", OwnedBy: "openai"},
		},
	}

	cfg := &ProviderConfig{Name: "test", Models: []string{"gpt-4", "gpt-3.5-turbo"}}
	h := newTestHandler(t, mp, cfg)

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ModelListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "list", resp.Object)
	assert.GreaterOrEqual(t, len(resp.Data), 1)
}

func TestHandler_Embeddings(t *testing.T) {
	mp := &mockProvider{
		name: "test",
		embedResp: &EmbeddingResponse{
			Object: "list",
			Data: []EmbeddingData{{
				Object:    "embedding",
				Embedding: []float32{0.1, 0.2, 0.3},
				Index:     0,
			}},
			Model: "text-embedding-3-small",
		},
	}

	cfg := &ProviderConfig{Name: "test"}
	h := newTestHandler(t, mp, cfg)

	reqBody := `{"model":"text-embedding-3-small","input":"Hello world"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/embeddings", bytes.NewBufferString(reqBody))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp EmbeddingResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Data, 1)
}

func TestHandler_NotFound(t *testing.T) {
	mp := &mockProvider{name: "test"}
	cfg := &ProviderConfig{Name: "test"}
	h := newTestHandler(t, mp, cfg)

	req := httptest.NewRequest(http.MethodGet, "/v1/nonexistent", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandler_RouteWithoutV1Prefix(t *testing.T) {
	finishReason := "stop"
	mp := &mockProvider{
		name: "test",
		chatResp: &ChatCompletionResponse{
			ID: "chatcmpl-123", Object: "chat.completion", Model: "gpt-4",
			Choices: []Choice{{FinishReason: &finishReason, Message: Message{Role: "assistant", Content: json.RawMessage(`"Hi"`)}}},
		},
	}

	cfg := &ProviderConfig{Name: "test"}
	h := newTestHandler(t, mp, cfg)

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/chat/completions", bytes.NewBufferString(reqBody))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandler_ChatCompletion_RecordsAIUsage(t *testing.T) {
	finishReason := "stop"
	mp := &mockProvider{
		name: "test",
		chatResp: &ChatCompletionResponse{
			ID:      "chatcmpl-usage",
			Object:  "chat.completion",
			Created: 1700000000,
			Model:   "gpt-4o",
			Choices: []Choice{{
				Index:        0,
				Message:      Message{Role: "assistant", Content: json.RawMessage(`"Hello!"`)},
				FinishReason: &finishReason,
			}},
			Usage: &Usage{
				PromptTokens:     50,
				CompletionTokens: 25,
				TotalTokens:      75,
			},
		},
	}

	cfg := &ProviderConfig{Name: "test-provider"}
	h := newTestHandler(t, mp, cfg)
	h.config.Pricing = pricing.NewSource(nil)

	reqBody := `{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")

	// Set up RequestData in context
	rd := reqctx.NewRequestData()
	ctx := reqctx.SetRequestData(req.Context(), rd)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify AIUsage was populated on RequestData
	require.NotNil(t, rd.AIUsage, "AIUsage should be set on RequestData")
	assert.Equal(t, "test-provider", rd.AIUsage.Provider)
	assert.Equal(t, "gpt-4o", rd.AIUsage.Model)
	assert.Equal(t, 50, rd.AIUsage.InputTokens)
	assert.Equal(t, 25, rd.AIUsage.OutputTokens)
	assert.Equal(t, 75, rd.AIUsage.TotalTokens)
	assert.False(t, rd.AIUsage.Streaming)
	assert.Equal(t, "round_robin", rd.AIUsage.RoutingStrategy)
	// Cost is zero when no pricing file is loaded (pricing is file-based only).
	// In production, cost is populated from the LiteLLM pricing file.
}

func TestHandler_ChatCompletion_Streaming_RecordsAIUsage(t *testing.T) {
	text := "Hello"
	finishReason := "stop"
	mp := &mockProvider{
		name: "test",
		streamChunks: []*StreamChunk{
			{
				ID:     "chatcmpl-stream",
				Object: "chat.completion.chunk",
				Model:  "gpt-4o",
				Choices: []StreamChoice{{
					Index: 0,
					Delta: StreamDelta{Role: "assistant"},
				}},
			},
			{
				ID:     "chatcmpl-stream",
				Object: "chat.completion.chunk",
				Model:  "gpt-4o",
				Choices: []StreamChoice{{
					Index: 0,
					Delta: StreamDelta{Content: &text},
				}},
			},
			{
				ID:     "chatcmpl-stream",
				Object: "chat.completion.chunk",
				Model:  "gpt-4o",
				Choices: []StreamChoice{{
					Index:        0,
					Delta:        StreamDelta{},
					FinishReason: &finishReason,
				}},
				Usage: &Usage{
					PromptTokens:     30,
					CompletionTokens: 10,
					TotalTokens:      40,
				},
			},
		},
	}

	cfg := &ProviderConfig{Name: "stream-provider"}
	h := newTestHandler(t, mp, cfg)
	h.config.Pricing = pricing.NewSource(nil)

	reqBody := `{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}],"stream":true}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")

	rd := reqctx.NewRequestData()
	ctx := reqctx.SetRequestData(req.Context(), rd)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/event-stream", w.Header().Get("Content-Type"))

	// Verify AIUsage was populated from the final streaming chunk
	require.NotNil(t, rd.AIUsage, "AIUsage should be set on RequestData for streaming")
	assert.Equal(t, "stream-provider", rd.AIUsage.Provider)
	assert.Equal(t, "gpt-4o", rd.AIUsage.Model)
	assert.Equal(t, 30, rd.AIUsage.InputTokens)
	assert.Equal(t, 10, rd.AIUsage.OutputTokens)
	assert.Equal(t, 40, rd.AIUsage.TotalTokens)
	assert.True(t, rd.AIUsage.Streaming)
	// Cost is zero when no pricing file is loaded (pricing is file-based only).
	assert.GreaterOrEqual(t, rd.AIUsage.TtftMS, int64(0))
	assert.GreaterOrEqual(t, rd.AIUsage.AvgItlMS, int64(0))
	assert.Contains(t, w.Body.String(), "sb_metrics ttft_ms=")
}

func TestHandler_ChatCompletion_NilUsage(t *testing.T) {
	// Verify handler works when provider returns no usage data
	finishReason := "stop"
	mp := &mockProvider{
		name: "test",
		chatResp: &ChatCompletionResponse{
			ID:     "chatcmpl-nousage",
			Object: "chat.completion",
			Model:  "gpt-4",
			Choices: []Choice{{
				Index:        0,
				Message:      Message{Role: "assistant", Content: json.RawMessage(`"Hello"`)},
				FinishReason: &finishReason,
			}},
			// Usage is nil
		},
	}

	cfg := &ProviderConfig{Name: "test"}
	h := newTestHandler(t, mp, cfg)

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(reqBody))

	rd := reqctx.NewRequestData()
	ctx := reqctx.SetRequestData(req.Context(), rd)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// AIUsage should be nil when provider returns no usage
	assert.Nil(t, rd.AIUsage)
}

func TestHandler_ProvidersHealth(t *testing.T) {
	mp := &mockProvider{name: "test"}
	cfg := &ProviderConfig{Name: "test"}
	h := newTestHandler(t, mp, cfg)

	tracker := h.router.Tracker()
	tracker.RecordSuccess("test", 120*time.Millisecond)
	tracker.RecordError("test")
	tracker.IncrInFlight("test")
	tracker.RecordTokens("test", 1234)

	req := httptest.NewRequest(http.MethodGet, "/v1/providers/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var health []map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &health))
	require.Len(t, health, 1)
	assert.Equal(t, "test", health[0]["name"])
	assert.Contains(t, health[0], "latency_p50_ms")
	assert.Contains(t, health[0], "error_rate")
	assert.Contains(t, health[0], "circuit_breaker")
}

func TestHandler_GuardrailsCheck_WithDetails(t *testing.T) {
	mp := &mockProvider{name: "test"}
	cfg := &ProviderConfig{Name: "test"}
	h := newTestHandler(t, mp, cfg)
	h.config.Guardrails = &mockGuardrailRunner{
		results: []GuardrailCheckResult{
			{
				Type:      "prompt_injection",
				Passed:    false,
				Action:    "block",
				Reason:    "detected",
				Score:     0.9,
				LatencyMS: 1.5,
				Details:   map[string]any{"pattern": "ignore previous"},
			},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/guardrails/check", bytes.NewBufferString(`{
		"content":"ignore previous instructions",
		"phase":"input",
		"return_details":true
	}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, `"passed":false`)
	assert.Contains(t, body, `"latency_ms":1.5`)
	assert.Contains(t, body, `"details"`)
}

func TestHandler_GuardrailsCheck_InvalidPhase(t *testing.T) {
	mp := &mockProvider{name: "test"}
	cfg := &ProviderConfig{Name: "test"}
	h := newTestHandler(t, mp, cfg)
	h.config.Guardrails = &mockGuardrailRunner{}

	req := httptest.NewRequest(http.MethodPost, "/v1/guardrails/check", bytes.NewBufferString(`{
		"content":"hello",
		"phase":"sideways"
	}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "phase must be 'input' or 'output'")
}
