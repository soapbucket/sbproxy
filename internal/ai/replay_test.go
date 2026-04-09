package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newReplayTestHandler(t *testing.T, mp *mockProvider, replayCfg *ReplayConfig) *Handler {
	t.Helper()
	cfg := &ProviderConfig{Name: "test"}
	providers := []*ProviderConfig{cfg}
	h := &Handler{
		config: &HandlerConfig{
			Providers:          providers,
			MaxRequestBodySize: 10 * 1024 * 1024,
			Replay:             replayCfg,
		},
		providers: map[string]providerEntry{
			"test": {provider: mp, config: cfg},
		},
		router: NewRouter(nil, providers),
	}
	return h
}

func newReplayTestHandlerMultiProvider(t *testing.T, providers map[string]*mockProvider, replayCfg *ReplayConfig) *Handler {
	t.Helper()
	var cfgs []*ProviderConfig
	entries := make(map[string]providerEntry)
	for name, mp := range providers {
		cfg := &ProviderConfig{Name: name}
		cfgs = append(cfgs, cfg)
		entries[name] = providerEntry{provider: mp, config: cfg}
	}
	h := &Handler{
		config: &HandlerConfig{
			Providers:          cfgs,
			MaxRequestBodySize: 10 * 1024 * 1024,
			Replay:             replayCfg,
		},
		providers: entries,
		router:    NewRouter(nil, cfgs),
	}
	return h
}

func testChatResponse(id, model, content string) *ChatCompletionResponse {
	finishReason := "stop"
	return &ChatCompletionResponse{
		ID:      id,
		Object:  "chat.completion",
		Created: 1700000000,
		Model:   model,
		Choices: []Choice{{
			Index:        0,
			Message:      Message{Role: "assistant", Content: json.RawMessage(`"` + content + `"`)},
			FinishReason: &finishReason,
		}},
		Usage: &Usage{
			PromptTokens:     10,
			CompletionTokens: 5,
			TotalTokens:      15,
		},
	}
}

func doReplayRequest(t *testing.T, h *Handler, req any, path string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/v1/"+path, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestReplayExecute(t *testing.T) {
	mp := &mockProvider{
		name:     "test",
		chatResp: testChatResponse("replay-1", "gpt-4", "Hello from replay!"),
	}
	h := newReplayTestHandler(t, mp, &ReplayConfig{Enabled: true})

	req := ReplayRequest{
		OriginalRequest: &ChatCompletionRequest{
			Model:    "gpt-4",
			Messages: []Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
		},
		Mode: "execute",
	}

	w := doReplayRequest(t, h, req, "replay")
	assert.Equal(t, http.StatusOK, w.Code)

	var resp ReplayResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "execute", resp.Mode)
	assert.Equal(t, "gpt-4", resp.Model)
	assert.Equal(t, "test", resp.Provider)
	assert.NotNil(t, resp.Response)
	assert.Equal(t, "replay-1", resp.Response.ID)
	assert.Nil(t, resp.DryRun)
	assert.Nil(t, resp.Diff)
	assert.GreaterOrEqual(t, resp.DurationMS, int64(0))

	// Verify streaming was forced off.
	require.NotNil(t, mp.lastChatReq)
	assert.False(t, mp.lastChatReq.IsStreaming())
}

func TestReplayDryRun(t *testing.T) {
	mp := &mockProvider{
		name:     "test",
		chatResp: testChatResponse("replay-1", "gpt-4", "should not execute"),
	}
	h := newReplayTestHandler(t, mp, &ReplayConfig{Enabled: true})

	req := ReplayRequest{
		OriginalRequest: &ChatCompletionRequest{
			Model:    "gpt-4",
			Messages: []Message{{Role: "user", Content: json.RawMessage(`"What is 2+2?"`)}},
		},
		Mode: "dry_run",
	}

	w := doReplayRequest(t, h, req, "replay")
	assert.Equal(t, http.StatusOK, w.Code)

	var resp ReplayResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "dry_run", resp.Mode)
	assert.Nil(t, resp.Response, "dry_run should not execute the request")
	assert.NotNil(t, resp.DryRun)
	assert.Equal(t, "test", resp.DryRun.TargetProvider)
	assert.Equal(t, "gpt-4", resp.DryRun.TargetModel)
	assert.Greater(t, resp.DryRun.EstimatedTokens, 0)
	assert.False(t, resp.DryRun.WouldBlock)

	// Verify the provider was never called.
	assert.Nil(t, mp.lastChatReq)
}

func TestReplayDryRun_GuardrailBlock(t *testing.T) {
	mp := &mockProvider{
		name:     "test",
		chatResp: testChatResponse("replay-1", "gpt-4", "blocked"),
	}
	h := newReplayTestHandler(t, mp, &ReplayConfig{Enabled: true})

	// Add a guardrail that blocks input.
	h.config.Guardrails = &mockBlockingGuardrail{
		blockName:   "safety",
		blockReason: "content policy violation",
	}

	req := ReplayRequest{
		OriginalRequest: &ChatCompletionRequest{
			Model:    "gpt-4",
			Messages: []Message{{Role: "user", Content: json.RawMessage(`"bad content"`)}},
		},
		Mode: "dry_run",
	}

	w := doReplayRequest(t, h, req, "replay")
	assert.Equal(t, http.StatusOK, w.Code)

	var resp ReplayResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.DryRun.WouldBlock)
	assert.Contains(t, resp.DryRun.BlockReason, "safety")
}

func TestReplayDiff_Match(t *testing.T) {
	mp := &mockProvider{
		name:     "test",
		chatResp: testChatResponse("replay-2", "gpt-4", "Hello!"),
	}
	h := newReplayTestHandler(t, mp, &ReplayConfig{Enabled: true})

	req := ReplayRequest{
		OriginalRequest: &ChatCompletionRequest{
			Model:    "gpt-4",
			Messages: []Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
		},
		OriginalResponse: testChatResponse("original-1", "gpt-4", "Hello!"),
		Mode:             "diff",
	}

	w := doReplayRequest(t, h, req, "replay")
	assert.Equal(t, http.StatusOK, w.Code)

	var resp ReplayResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "diff", resp.Mode)
	assert.NotNil(t, resp.Diff)
	assert.True(t, resp.Diff.Match)
	assert.False(t, resp.Diff.ContentChanged)
	assert.False(t, resp.Diff.ModelChanged)
	assert.Equal(t, "Hello!", resp.Diff.OriginalContent)
	assert.Equal(t, "Hello!", resp.Diff.ReplayContent)
	assert.Equal(t, 0, resp.Diff.TokenDiff)
}

func TestReplayDiff_Mismatch(t *testing.T) {
	mp := &mockProvider{
		name: "test",
		chatResp: &ChatCompletionResponse{
			ID:      "replay-3",
			Object:  "chat.completion",
			Created: 1700000000,
			Model:   "gpt-4-turbo",
			Choices: []Choice{{
				Index:   0,
				Message: Message{Role: "assistant", Content: json.RawMessage(`"Different answer"`)},
			}},
			Usage: &Usage{TotalTokens: 20},
		},
	}
	h := newReplayTestHandler(t, mp, &ReplayConfig{Enabled: true})

	req := ReplayRequest{
		OriginalRequest: &ChatCompletionRequest{
			Model:    "gpt-4",
			Messages: []Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
		},
		OriginalResponse: testChatResponse("original-1", "gpt-4", "Original answer"),
		Mode:             "diff",
	}

	w := doReplayRequest(t, h, req, "replay")
	assert.Equal(t, http.StatusOK, w.Code)

	var resp ReplayResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Diff.Match)
	assert.True(t, resp.Diff.ContentChanged)
	assert.True(t, resp.Diff.ModelChanged)
	assert.Equal(t, "Original answer", resp.Diff.OriginalContent)
	assert.Equal(t, "Different answer", resp.Diff.ReplayContent)
	assert.Equal(t, 5, resp.Diff.TokenDiff) // 20 - 15
}

func TestReplayDiff_MissingOriginalResponse(t *testing.T) {
	mp := &mockProvider{
		name:     "test",
		chatResp: testChatResponse("replay-1", "gpt-4", "Hello"),
	}
	h := newReplayTestHandler(t, mp, &ReplayConfig{Enabled: true})

	req := ReplayRequest{
		OriginalRequest: &ChatCompletionRequest{
			Model:    "gpt-4",
			Messages: []Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
		},
		Mode: "diff",
	}

	w := doReplayRequest(t, h, req, "replay")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestReplayProviderOverride(t *testing.T) {
	altProvider := &mockProvider{
		name:     "alt",
		chatResp: testChatResponse("alt-1", "gpt-4", "From alt provider"),
	}
	mainProvider := &mockProvider{
		name:     "test",
		chatResp: testChatResponse("main-1", "gpt-4", "From main provider"),
	}

	h := newReplayTestHandlerMultiProvider(t, map[string]*mockProvider{
		"test": mainProvider,
		"alt":  altProvider,
	}, &ReplayConfig{Enabled: true})

	req := ReplayRequest{
		OriginalRequest: &ChatCompletionRequest{
			Model:    "gpt-4",
			Messages: []Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
		},
		Provider: "alt",
		Mode:     "execute",
	}

	w := doReplayRequest(t, h, req, "replay")
	assert.Equal(t, http.StatusOK, w.Code)

	var resp ReplayResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "alt", resp.Provider)
	assert.Equal(t, "alt-1", resp.Response.ID)
}

func TestReplayProviderOverride_NotFound(t *testing.T) {
	mp := &mockProvider{
		name:     "test",
		chatResp: testChatResponse("replay-1", "gpt-4", "Hello"),
	}
	h := newReplayTestHandler(t, mp, &ReplayConfig{Enabled: true})

	req := ReplayRequest{
		OriginalRequest: &ChatCompletionRequest{
			Model:    "gpt-4",
			Messages: []Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
		},
		Provider: "nonexistent",
		Mode:     "execute",
	}

	w := doReplayRequest(t, h, req, "replay")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestReplayModelOverride(t *testing.T) {
	mp := &mockProvider{
		name:     "test",
		chatResp: testChatResponse("replay-1", "gpt-3.5-turbo", "Hello from 3.5"),
	}
	h := newReplayTestHandler(t, mp, &ReplayConfig{Enabled: true})

	req := ReplayRequest{
		OriginalRequest: &ChatCompletionRequest{
			Model:    "gpt-4",
			Messages: []Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
		},
		Model: "gpt-3.5-turbo",
		Mode:  "execute",
	}

	w := doReplayRequest(t, h, req, "replay")
	assert.Equal(t, http.StatusOK, w.Code)

	var resp ReplayResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "gpt-3.5-turbo", resp.Model)

	// Verify the overridden model was sent to the provider.
	require.NotNil(t, mp.lastChatReq)
	assert.Equal(t, "gpt-3.5-turbo", mp.lastChatReq.Model)
}

func TestReplayStreamingForceOff(t *testing.T) {
	mp := &mockProvider{
		name:     "test",
		chatResp: testChatResponse("replay-1", "gpt-4", "Hello"),
	}
	h := newReplayTestHandler(t, mp, &ReplayConfig{Enabled: true})

	streamOn := true
	req := ReplayRequest{
		OriginalRequest: &ChatCompletionRequest{
			Model:    "gpt-4",
			Messages: []Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
			Stream:   &streamOn,
			StreamOptions: &StreamOptions{IncludeUsage: true},
		},
		Mode: "execute",
	}

	w := doReplayRequest(t, h, req, "replay")
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify streaming was forced off.
	require.NotNil(t, mp.lastChatReq)
	assert.False(t, mp.lastChatReq.IsStreaming())
	assert.Nil(t, mp.lastChatReq.StreamOptions)
}

func TestBatchReplay(t *testing.T) {
	callCount := 0
	mp := &mockProvider{
		name: "test",
		chatResp: testChatResponse("batch-1", "gpt-4", "Batch response"),
	}
	// Track calls by overriding chatResp per call isn't possible with this mock,
	// but we can verify the batch response structure.
	_ = callCount
	h := newReplayTestHandler(t, mp, &ReplayConfig{Enabled: true, MaxBatch: 10})

	batchReq := BatchReplayRequest{
		Requests: []ReplayRequest{
			{
				OriginalRequest: &ChatCompletionRequest{
					Model:    "gpt-4",
					Messages: []Message{{Role: "user", Content: json.RawMessage(`"First"`)}},
				},
				Mode: "execute",
			},
			{
				OriginalRequest: &ChatCompletionRequest{
					Model:    "gpt-4",
					Messages: []Message{{Role: "user", Content: json.RawMessage(`"Second"`)}},
				},
				Mode: "execute",
			},
			{
				OriginalRequest: &ChatCompletionRequest{
					Model:    "gpt-4",
					Messages: []Message{{Role: "user", Content: json.RawMessage(`"Third"`)}},
				},
				Mode: "dry_run",
			},
		},
	}

	w := doReplayRequest(t, h, batchReq, "replay/batch")
	assert.Equal(t, http.StatusOK, w.Code)

	var resp BatchReplayResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 3, resp.TotalCount)
	assert.Equal(t, 3, resp.SuccessCount)
	assert.Equal(t, 0, resp.ErrorCount)
	assert.Len(t, resp.Results, 3)
	assert.Equal(t, "execute", resp.Results[0].Mode)
	assert.Equal(t, "execute", resp.Results[1].Mode)
	assert.Equal(t, "dry_run", resp.Results[2].Mode)
	assert.GreaterOrEqual(t, resp.TotalDurationMS, int64(0))
}

func TestBatchReplay_MaxLimit(t *testing.T) {
	mp := &mockProvider{
		name:     "test",
		chatResp: testChatResponse("batch-1", "gpt-4", "response"),
	}
	h := newReplayTestHandler(t, mp, &ReplayConfig{Enabled: true, MaxBatch: 2})

	batchReq := BatchReplayRequest{
		Requests: []ReplayRequest{
			{OriginalRequest: &ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: json.RawMessage(`"1"`)}}}},
			{OriginalRequest: &ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: json.RawMessage(`"2"`)}}}},
			{OriginalRequest: &ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: json.RawMessage(`"3"`)}}}},
		},
	}

	w := doReplayRequest(t, h, batchReq, "replay/batch")
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var errResp ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &errResp))
	assert.Contains(t, errResp.Error.Message, "exceeds maximum of 2")
}

func TestBatchReplay_EmptyRequests(t *testing.T) {
	mp := &mockProvider{
		name:     "test",
		chatResp: testChatResponse("batch-1", "gpt-4", "response"),
	}
	h := newReplayTestHandler(t, mp, &ReplayConfig{Enabled: true})

	batchReq := BatchReplayRequest{
		Requests: []ReplayRequest{},
	}

	w := doReplayRequest(t, h, batchReq, "replay/batch")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBatchReplay_NilOriginalRequest(t *testing.T) {
	mp := &mockProvider{
		name:     "test",
		chatResp: testChatResponse("batch-1", "gpt-4", "response"),
	}
	h := newReplayTestHandler(t, mp, &ReplayConfig{Enabled: true})

	batchReq := BatchReplayRequest{
		Requests: []ReplayRequest{
			{OriginalRequest: nil, Mode: "execute"},
			{OriginalRequest: &ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: json.RawMessage(`"ok"`)}}}, Mode: "execute"},
		},
	}

	w := doReplayRequest(t, h, batchReq, "replay/batch")
	assert.Equal(t, http.StatusOK, w.Code)

	var resp BatchReplayResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 2, resp.TotalCount)
	assert.Equal(t, 1, resp.SuccessCount)
	assert.Equal(t, 1, resp.ErrorCount)
}

func TestReplayDisabled(t *testing.T) {
	mp := &mockProvider{
		name:     "test",
		chatResp: testChatResponse("replay-1", "gpt-4", "Hello"),
	}

	tests := []struct {
		name   string
		config *ReplayConfig
	}{
		{"nil config", nil},
		{"disabled", &ReplayConfig{Enabled: false}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newReplayTestHandler(t, mp, tt.config)

			req := ReplayRequest{
				OriginalRequest: &ChatCompletionRequest{
					Model:    "gpt-4",
					Messages: []Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
				},
			}

			w := doReplayRequest(t, h, req, "replay")
			assert.Equal(t, http.StatusNotFound, w.Code)

			// Batch should also return 404.
			batchReq := BatchReplayRequest{
				Requests: []ReplayRequest{req},
			}
			w = doReplayRequest(t, h, batchReq, "replay/batch")
			assert.Equal(t, http.StatusNotFound, w.Code)
		})
	}
}

func TestReplayMissingOriginalRequest(t *testing.T) {
	mp := &mockProvider{
		name:     "test",
		chatResp: testChatResponse("replay-1", "gpt-4", "Hello"),
	}
	h := newReplayTestHandler(t, mp, &ReplayConfig{Enabled: true})

	req := ReplayRequest{
		OriginalRequest: nil,
		Mode:            "execute",
	}

	w := doReplayRequest(t, h, req, "replay")
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var errResp ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &errResp))
	assert.Contains(t, errResp.Error.Message, "original_request is required")
}

func TestReplayDefaultMode(t *testing.T) {
	mp := &mockProvider{
		name:     "test",
		chatResp: testChatResponse("replay-1", "gpt-4", "Hello"),
	}
	h := newReplayTestHandler(t, mp, &ReplayConfig{Enabled: true})

	// No mode specified should default to "execute".
	req := ReplayRequest{
		OriginalRequest: &ChatCompletionRequest{
			Model:    "gpt-4",
			Messages: []Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
		},
	}

	w := doReplayRequest(t, h, req, "replay")
	assert.Equal(t, http.StatusOK, w.Code)

	var resp ReplayResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "execute", resp.Mode)
	assert.NotNil(t, resp.Response)
}

func TestReplayMethodNotAllowed(t *testing.T) {
	mp := &mockProvider{
		name:     "test",
		chatResp: testChatResponse("replay-1", "gpt-4", "Hello"),
	}
	h := newReplayTestHandler(t, mp, &ReplayConfig{Enabled: true})

	r := httptest.NewRequest(http.MethodGet, "/v1/replay", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// mockBlockingGuardrail is a guardrail runner that always blocks input.
type mockBlockingGuardrail struct {
	blockName   string
	blockReason string
}

func (m *mockBlockingGuardrail) CheckInput(_ context.Context, messages []Message, _ string) ([]Message, *GuardrailBlock, error) {
	return messages, &GuardrailBlock{Name: m.blockName, Reason: m.blockReason}, nil
}

func (m *mockBlockingGuardrail) CheckOutput(_ context.Context, messages []Message, _ string) ([]Message, *GuardrailBlock, error) {
	return messages, nil, nil
}

func (m *mockBlockingGuardrail) HasInput() bool  { return true }
func (m *mockBlockingGuardrail) HasOutput() bool { return false }

func (m *mockBlockingGuardrail) CheckContent(_ context.Context, _ string, _ string, _ string, _ []string) ([]GuardrailCheckResult, error) {
	return nil, nil
}
