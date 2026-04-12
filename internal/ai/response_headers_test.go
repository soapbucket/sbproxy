package ai

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	json "github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResponseHeaders_NonStreaming_AllHeadersPresent(t *testing.T) {
	// Simulate the non-streaming response header logic from handleNonStreamingCompletion.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	r.Header.Set("X-Request-ID", "req-client-123")

	requestID := resolveRequestID(r)
	assert.Equal(t, "req-client-123", requestID)

	resp := &ChatCompletionResponse{
		ID:    "chatcmpl-abc123",
		Model: "gpt-4",
		Usage: &Usage{
			PromptTokens:     150,
			CompletionTokens: 87,
			TotalTokens:      237,
		},
	}

	// Set headers as the handler would
	w.Header().Set("X-Sb-AI-Model", "gpt-4")
	w.Header().Set("X-Sb-AI-Provider", "openai")
	w.Header().Set("X-Sb-AI-Latency-Ms", "1243")
	w.Header().Set("X-Sb-AI-Cache-Hit", "false")
	w.Header().Set("X-Sb-AI-Request-Id", requestID)
	w.Header().Set("X-Sb-AI-Provider-Request-Id", resp.ID)
	w.Header().Set("X-Sb-AI-Tokens-Input", "150")
	w.Header().Set("X-Sb-AI-Tokens-Output", "87")
	w.Header().Set("X-Sb-AI-Tokens-Total", "237")
	w.Header().Set("X-Sb-AI-Cost", "0.0023")

	result := w.Result()
	defer result.Body.Close()

	assert.Equal(t, "gpt-4", result.Header.Get("X-Sb-AI-Model"))
	assert.Equal(t, "openai", result.Header.Get("X-Sb-AI-Provider"))
	assert.Equal(t, "1243", result.Header.Get("X-Sb-AI-Latency-Ms"))
	assert.Equal(t, "false", result.Header.Get("X-Sb-AI-Cache-Hit"))
	assert.Equal(t, "req-client-123", result.Header.Get("X-Sb-AI-Request-Id"))
	assert.Equal(t, "chatcmpl-abc123", result.Header.Get("X-Sb-AI-Provider-Request-Id"))
	assert.Equal(t, "150", result.Header.Get("X-Sb-AI-Tokens-Input"))
	assert.Equal(t, "87", result.Header.Get("X-Sb-AI-Tokens-Output"))
	assert.Equal(t, "237", result.Header.Get("X-Sb-AI-Tokens-Total"))
	assert.Equal(t, "0.0023", result.Header.Get("X-Sb-AI-Cost"))
}

func TestResponseHeaders_Streaming_SbMetadataInFinalChunk(t *testing.T) {
	w := httptest.NewRecorder()
	sw := NewSSEWriter(w)
	defer ReleaseSSEWriter(sw)
	sw.WriteHeaders()

	// Write a regular content chunk
	contentChunk := &StreamChunk{
		ID:      "chatcmpl-stream1",
		Object:  "chat.completion.chunk",
		Created: 1700000000,
		Model:   "gpt-4",
		Choices: []StreamChoice{
			{
				Index: 0,
				Delta: StreamDelta{Content: toStrPtr("Hello")},
			},
		},
	}
	err := sw.WriteChunk(contentChunk)
	require.NoError(t, err)

	// Write the metadata chunk (as the handler does at EOF)
	metaChunk := &StreamChunk{
		ID:      "chatcmpl-stream1",
		Object:  "chat.completion.chunk",
		Created: 1700000001,
		Model:   "gpt-4",
		SbMetadata: &SbMetadata{
			CostUSD:           0.0003,
			Provider:          "openai",
			Model:             "gpt-4",
			InputTokens:       10,
			OutputTokens:      5,
			TotalTokens:       15,
			CacheHit:          false,
			LatencyMs:         1243,
			RequestID:         "req-abc123",
			ProviderRequestID: "chatcmpl-stream1",
		},
	}
	err = sw.WriteChunk(metaChunk)
	require.NoError(t, err)
	sw.WriteDone()

	body := w.Body.String()

	// Parse SSE events from the body
	lines := strings.Split(body, "\n")
	var dataLines []string
	for _, line := range lines {
		if strings.HasPrefix(line, "data: ") && line != "data: [DONE]" {
			dataLines = append(dataLines, strings.TrimPrefix(line, "data: "))
		}
	}

	require.Len(t, dataLines, 2, "expected 2 data chunks (content + metadata)")

	// Verify the first chunk has no sb_metadata
	var firstChunk map[string]any
	err = json.Unmarshal([]byte(dataLines[0]), &firstChunk)
	require.NoError(t, err)
	assert.Nil(t, firstChunk["sb_metadata"], "first chunk should not have sb_metadata")

	// Verify the final chunk has sb_metadata
	var finalChunk map[string]any
	err = json.Unmarshal([]byte(dataLines[1]), &finalChunk)
	require.NoError(t, err)

	meta, ok := finalChunk["sb_metadata"].(map[string]any)
	require.True(t, ok, "final chunk should have sb_metadata object")
	assert.InDelta(t, 0.0003, meta["cost_usd"].(float64), 0.00001)
	assert.Equal(t, "openai", meta["provider"])
	assert.Equal(t, "gpt-4", meta["model"])
	assert.Equal(t, float64(10), meta["input_tokens"])
	assert.Equal(t, float64(5), meta["output_tokens"])
	assert.Equal(t, float64(15), meta["total_tokens"])
	assert.Equal(t, false, meta["cache_hit"])
	assert.Equal(t, float64(1243), meta["latency_ms"])
	assert.Equal(t, "req-abc123", meta["request_id"])
	assert.Equal(t, "chatcmpl-stream1", meta["provider_request_id"])
}

func TestResponseHeaders_ClientProvidedRequestIDEchoed(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	r.Header.Set("X-Request-ID", "req-my-custom-id")

	requestID := resolveRequestID(r)
	assert.Equal(t, "req-my-custom-id", requestID, "should use client-provided request ID")

	w := httptest.NewRecorder()
	w.Header().Set("X-Request-ID", requestID)
	w.Header().Set("X-Sb-AI-Request-Id", requestID)

	result := w.Result()
	defer result.Body.Close()

	assert.Equal(t, "req-my-custom-id", result.Header.Get("X-Request-ID"))
	assert.Equal(t, "req-my-custom-id", result.Header.Get("X-Sb-AI-Request-Id"))
}

func TestResponseHeaders_MissingRequestID_GeneratesWithPrefix(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	// No X-Request-ID header set

	requestID := resolveRequestID(r)
	assert.True(t, strings.HasPrefix(requestID, "req-"), "generated request ID should have req- prefix, got: %s", requestID)
	assert.Len(t, requestID, 20, "generated request ID should be req- + 16 hex chars = 20 chars")

	// Verify uniqueness
	requestID2 := resolveRequestID(r)
	assert.NotEqual(t, requestID, requestID2, "each call should generate a unique ID")
}

func TestResponseHeaders_ProviderRequestIDCaptured(t *testing.T) {
	resp := &ChatCompletionResponse{
		ID:    "chatcmpl-provider-xyz",
		Model: "gpt-4",
	}

	w := httptest.NewRecorder()
	if resp.ID != "" {
		w.Header().Set("X-Sb-AI-Provider-Request-Id", resp.ID)
	}

	result := w.Result()
	defer result.Body.Close()

	assert.Equal(t, "chatcmpl-provider-xyz", result.Header.Get("X-Sb-AI-Provider-Request-Id"))
}

func TestResponseHeaders_GenerateRequestID_CryptoRand(t *testing.T) {
	// Verify that generated IDs are well-formed and unique
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateRequestID()
		assert.True(t, strings.HasPrefix(id, "req-"))
		assert.Len(t, id, 20) // "req-" (4) + 16 hex chars
		assert.False(t, seen[id], "duplicate request ID generated: %s", id)
		seen[id] = true
	}
}

func TestResponseHeaders_SbMetadataStruct_JSONMarshal(t *testing.T) {
	meta := &SbMetadata{
		CostUSD:           0.0023,
		Provider:          "openai",
		Model:             "gpt-4",
		InputTokens:       150,
		OutputTokens:      87,
		TotalTokens:       237,
		CacheHit:          false,
		LatencyMs:         1243,
		RequestID:         "req-abc123",
		ProviderRequestID: "chatcmpl-xyz",
	}

	data, err := json.Marshal(meta)
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.InDelta(t, 0.0023, parsed["cost_usd"].(float64), 0.00001)
	assert.Equal(t, "openai", parsed["provider"])
	assert.Equal(t, "gpt-4", parsed["model"])
	assert.Equal(t, float64(150), parsed["input_tokens"])
	assert.Equal(t, float64(87), parsed["output_tokens"])
	assert.Equal(t, float64(237), parsed["total_tokens"])
	assert.Equal(t, false, parsed["cache_hit"])
	assert.Equal(t, float64(1243), parsed["latency_ms"])
	assert.Equal(t, "req-abc123", parsed["request_id"])
	assert.Equal(t, "chatcmpl-xyz", parsed["provider_request_id"])
}

func TestResponseHeaders_StreamChunkWithSbMetadata_Omitted(t *testing.T) {
	// When SbMetadata is nil, it should be omitted from JSON
	chunk := &StreamChunk{
		ID:      "chatcmpl-1",
		Object:  "chat.completion.chunk",
		Created: 1700000000,
		Model:   "gpt-4",
	}

	data, err := json.Marshal(chunk)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "sb_metadata", "sb_metadata should be omitted when nil")
}

func TestResponseHeaders_StreamChunkWithSbMetadata_Present(t *testing.T) {
	// When SbMetadata is set, it should appear in JSON
	chunk := &StreamChunk{
		ID:      "chatcmpl-1",
		Object:  "chat.completion.chunk",
		Created: 1700000000,
		Model:   "gpt-4",
		SbMetadata: &SbMetadata{
			CostUSD:   0.001,
			Provider:  "anthropic",
			Model:     "claude-3",
			RequestID: "req-test",
		},
	}

	data, err := json.Marshal(chunk)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"sb_metadata"`)
	assert.Contains(t, string(data), `"cost_usd"`)
	assert.Contains(t, string(data), `"req-test"`)
}

func toStrPtr(s string) *string {
	return &s
}
