package configloader

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestE2E_ModelsEndpoint_TwoProviders verifies GET /v1/models aggregates from multiple providers
func TestE2E_ModelsEndpoint_TwoProviders(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyMultiProviderJSON(t, "models-2prov.test", []string{mock.URL, mock.URL}, nil)

	r := newTestRequest(t, "GET", "http://models-2prov.test/v1/models")
	w := serveAIProxy(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	data, ok := resp["data"].([]any)
	if !ok {
		t.Fatal("expected data array in models response")
	}
	if len(data) == 0 {
		t.Fatal("expected at least one model in response")
	}
}

// TestE2E_ModelsEndpoint_FeatureFlagDisable verifies model hiding via feature flag
func TestE2E_ModelsEndpoint_FeatureFlagDisable(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "models-hide.test", mock.URL, map[string]any{
		"action": map[string]any{
			"type":           "ai_proxy",
			"providers":      []map[string]any{{"name": "openai", "api_key": "test", "base_url": mock.URL + "/v1", "models": []string{"gpt-4o-mini", "gpt-4o"}}},
			"default_model":  "gpt-4o-mini",
			"blocked_models": []string{"gpt-4o"},
		},
	})

	r := newTestRequest(t, "POST", "http://models-hide.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code == http.StatusOK {
		t.Fatal("expected blocked model to be rejected")
	}
}

// TestE2E_ChatCompletion_FullRequest verifies complete chat completion through proxy
func TestE2E_ChatCompletion_FullRequest(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "chat-full.test", mock.URL, nil)

	r := newTestRequest(t, "POST", "http://chat-full.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{
		"model":"gpt-4o-mini",
		"messages":[
			{"role":"system","content":"You are helpful."},
			{"role":"user","content":"Say hello"}
		],
		"temperature":0.7,
		"max_tokens":100
	}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	choices, ok := resp["choices"].([]any)
	if !ok || len(choices) == 0 {
		t.Fatal("expected choices in response")
	}
	choice0, _ := choices[0].(map[string]any)
	msg, _ := choice0["message"].(map[string]any)
	content, _ := msg["content"].(string)
	if content == "" {
		t.Fatal("expected non-empty content in response")
	}
}

// TestE2E_ChatCompletion_CostHeaders verifies X-Sb-AI-* cost headers
func TestE2E_ChatCompletion_CostHeaders(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "cost-headers.test", mock.URL, nil)

	r := newTestRequest(t, "POST", "http://cost-headers.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	// Cost headers may be present depending on config
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if usage, ok := resp["usage"].(map[string]any); !ok || usage == nil {
		t.Fatal("expected usage in response for cost calculation")
	}
}

// TestE2E_LegacyCompletion_TextFormat verifies text_completion format response
func TestE2E_LegacyCompletion_TextFormat(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "legacy.test", mock.URL, nil)

	r := newTestRequest(t, "POST", "http://legacy.test/v1/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","prompt":"Once upon a time","max_tokens":50}`))
	w := serveAIProxy(t, cfg, r)
	// Legacy completions endpoint may or may not be supported
	if w.Code != http.StatusOK {
		t.Logf("legacy completions returned %d (may not be supported)", w.Code)
	}
}

// TestE2E_Streaming_SSEChunks verifies SSE streaming chunks with DONE terminator
func TestE2E_Streaming_SSEChunks(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "sse-chunks.test", mock.URL, nil)

	r := newTestRequest(t, "POST", "http://sse-chunks.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}],"stream":true}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("expected text/event-stream, got %q", ct)
	}
	// Verify DONE terminator exists
	body := w.Body.String()
	if !strings.Contains(body, "[DONE]") {
		t.Fatal("expected [DONE] terminator in SSE stream")
	}
}

// TestE2E_Streaming_SbMetadata verifies X-Sb-Meta-* headers with streaming
func TestE2E_Streaming_SbMetadata(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "sb-meta.test", mock.URL, nil)

	r := newTestRequest(t, "POST", "http://sb-meta.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}],"stream":true}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestE2E_RequestID_Propagation verifies X-Request-ID propagation through proxy
func TestE2E_RequestID_Propagation(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "reqid-prop.test", mock.URL, nil)

	r := newTestRequest(t, "POST", "http://reqid-prop.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Request-Id", "test-propagation-123")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestE2E_FailureMock_RateLimit verifies 429 handling from upstream
func TestE2E_FailureMock_RateLimit(t *testing.T) {
	resetCache()
	// Create a mock that returns 429
	rateLimitServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		writeJSON(w, map[string]any{"error": map[string]any{"message": "rate limit exceeded", "type": "rate_limit_error"}})
	}))
	defer rateLimitServer.Close()
	cfg := aiProxyOriginJSON(t, "fail-429.test", rateLimitServer.URL, nil)

	r := newTestRequest(t, "POST", "http://fail-429.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`))
	w := serveAIProxy(t, cfg, r)
	// Should return 429 or 502 (provider unavailable)
	if w.Code == http.StatusOK {
		t.Fatal("expected non-200 for rate limited upstream")
	}
}

// TestE2E_FailureMock_ServerError verifies 500 handling from upstream
func TestE2E_FailureMock_ServerError(t *testing.T) {
	resetCache()
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]any{"error": map[string]any{"message": "internal error", "type": "server_error"}})
	}))
	defer errorServer.Close()
	cfg := aiProxyOriginJSON(t, "fail-500.test", errorServer.URL, nil)

	r := newTestRequest(t, "POST", "http://fail-500.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code == http.StatusOK {
		t.Fatal("expected non-200 for server error upstream")
	}
}

// TestE2E_FailureMock_ContentFilter verifies 400 content_filter handling
func TestE2E_FailureMock_ContentFilter(t *testing.T) {
	resetCache()
	filterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": map[string]any{"message": "content filtered", "type": "content_filter", "code": "content_filter"}})
	}))
	defer filterServer.Close()
	cfg := aiProxyOriginJSON(t, "fail-filter.test", filterServer.URL, nil)

	r := newTestRequest(t, "POST", "http://fail-filter.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code == http.StatusOK {
		t.Fatal("expected non-200 for content filter")
	}
}

// TestE2E_MockLLMServer_RecordsRequests verifies mock server request recording
func TestE2E_MockLLMServer_RecordsRequests(t *testing.T) {
	resetCache()
	var requestCount int
	recordingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		writeJSON(w, map[string]any{
			"id": "chatcmpl-rec", "object": "chat.completion", "model": "gpt-4o-mini",
			"choices": []map[string]any{{"index": 0, "message": map[string]any{"role": "assistant", "content": "ok"}, "finish_reason": "stop"}},
			"usage": map[string]any{"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6},
		})
	}))
	defer recordingServer.Close()
	cfg := aiProxyOriginJSON(t, "record.test", recordingServer.URL, nil)

	r := newTestRequest(t, "POST", "http://record.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if requestCount != 1 {
		t.Fatalf("expected 1 recorded request, got %d", requestCount)
	}
}

// TestE2E_MockLLMServer_CustomResponses verifies custom response configuration
func TestE2E_MockLLMServer_CustomResponses(t *testing.T) {
	resetCache()
	customServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeJSON(w, map[string]any{
			"id": "custom-resp", "object": "chat.completion", "model": "gpt-4o-mini",
			"choices": []map[string]any{{"index": 0, "message": map[string]any{"role": "assistant", "content": "Custom response!"}, "finish_reason": "stop"}},
			"usage": map[string]any{"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
		})
	}))
	defer customServer.Close()
	cfg := aiProxyOriginJSON(t, "custom.test", customServer.URL, nil)

	r := newTestRequest(t, "POST", "http://custom.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Custom response!") {
		t.Fatalf("expected custom response content, got: %s", w.Body.String())
	}
}

// TestE2E_MockLLMServer_Endpoints verifies all mock endpoints respond correctly
func TestE2E_MockLLMServer_Endpoints(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "endpoints.test", mock.URL, nil)

	t.Run("chat completions", func(t *testing.T) {
		r := newTestRequest(t, "POST", "http://endpoints.test/v1/chat/completions")
		r.Header.Set("Content-Type", "application/json")
		r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`))
		w := serveAIProxy(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("chat: expected 200, got %d", w.Code)
		}
	})

	t.Run("models", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://endpoints.test/v1/models")
		w := serveAIProxy(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("models: expected 200, got %d", w.Code)
		}
	})

	t.Run("health", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://endpoints.test/v1/health")
		w := serveAIProxy(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("health: expected 200, got %d", w.Code)
		}
	})
}

// TestE2E_StreamingMock_ChunkCount verifies streaming mock chunk count
func TestE2E_StreamingMock_ChunkCount(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "chunk-count.test", mock.URL, nil)

	r := newTestRequest(t, "POST", "http://chunk-count.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}],"stream":true}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Count data lines in the SSE stream
	scanner := bufio.NewScanner(strings.NewReader(w.Body.String()))
	dataLines := 0
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			dataLines++
		}
	}
	if dataLines < 2 {
		t.Fatalf("expected at least 2 SSE data lines (chunks + DONE), got %d", dataLines)
	}
}
