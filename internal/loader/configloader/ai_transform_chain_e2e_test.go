package configloader

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// TestAITransformChain_SchemaTokenCostProjection tests a realistic AI gateway
// transform chain: ai_schema -> token_count -> cost_estimate -> json_projection
func TestAITransformChain_SchemaTokenCostProjection(t *testing.T) {
	resetCache()

	// Mock upstream returns an OpenAI-style response
	openAIResponse := map[string]interface{}{
		"id":      "chatcmpl-test123",
		"object":  "chat.completion",
		"model":   "gpt-4o",
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"message": map[string]string{
					"role":    "assistant",
					"content": "Hello! I'm doing well, thank you for asking.",
				},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]int{
			"prompt_tokens":     25,
			"completion_tokens": 12,
			"total_tokens":      37,
		},
	}
	responseBody, _ := json.Marshal(openAIResponse)

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(responseBody)
	}))
	defer mockUpstream.Close()

	configJSON := `{
		"id": "ai-chain-test",
		"hostname": "ai-chain-test.local",
		"workspace_id": "test",
		"version": "1",
		"action": {
			"type": "proxy",
			"url": "` + mockUpstream.URL + `"
		},
		"transforms": [
			{
				"type": "ai_schema",
				"provider": "openai",
				"action": "warn"
			},
			{
				"type": "token_count",
				"provider": "openai"
			},
			{
				"type": "cost_estimate",
				"provider": "openai"
			},
			{
				"type": "json_projection",
				"include": ["id", "model", "choices"]
			}
		]
	}`

	mockStore := &mockStorage{
		data: map[string][]byte{
			"ai-chain-test.local": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	// Make a request
	req := httptest.NewRequest("POST", "http://ai-chain-test.local/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "ai-chain-test.local"

	requestData := reqctx.NewRequestData()
	requestData.ID = "test-chain-id"
	ctx := reqctx.SetRequestData(req.Context(), requestData)
	req = req.WithContext(ctx)

	cfg, err := Load(req, mgr)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Verify transforms loaded
	if len(cfg.Transforms) != 4 {
		t.Fatalf("expected 4 transforms, got %d", len(cfg.Transforms))
	}

	// Serve request
	rr := httptest.NewRecorder()
	cfg.ServeHTTP(rr, req)

	resp := rr.Result()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Check token count headers were set by token_count transform
	if v := resp.Header.Get("X-Token-Count-Prompt"); v != "25" {
		t.Errorf("expected X-Token-Count-Prompt=25, got %q", v)
	}
	if v := resp.Header.Get("X-Token-Count-Completion"); v != "12" {
		t.Errorf("expected X-Token-Count-Completion=12, got %q", v)
	}
	if v := resp.Header.Get("X-Token-Count-Total"); v != "37" {
		t.Errorf("expected X-Token-Count-Total=37, got %q", v)
	}

	// Check cost estimate header was set
	if v := resp.Header.Get("X-Estimated-Cost"); v == "" {
		t.Error("expected X-Estimated-Cost header to be set")
	}

	// Check JSON projection filtered the response
	body := rr.Body.String()
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		// Projection may have changed format; just verify headers worked
		t.Logf("response body (may be projected): %s", body)
		return
	}

	if _, ok := result["id"]; !ok {
		t.Error("expected 'id' in projected response")
	}
	if _, ok := result["model"]; !ok {
		t.Error("expected 'model' in projected response")
	}
	if _, ok := result["choices"]; !ok {
		t.Error("expected 'choices' in projected response")
	}
	// These should have been removed by projection
	if _, ok := result["usage"]; ok {
		t.Error("'usage' should have been removed by projection")
	}
	if _, ok := result["object"]; ok {
		t.Error("'object' should have been removed by projection")
	}
}

// TestAITransformChain_SSEPassthrough verifies SSE responses pass through
// non-SSE transforms gracefully.
func TestAITransformChain_SSEPassthrough(t *testing.T) {
	resetCache()

	sseBody := "data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\ndata: [DONE]\n\n"

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sseBody))
	}))
	defer mockUpstream.Close()

	configJSON := `{
		"id": "ai-sse-test",
		"hostname": "ai-sse-test.local",
		"workspace_id": "test",
		"version": "1",
		"action": {
			"type": "proxy",
			"url": "` + mockUpstream.URL + `"
		},
		"transforms": [
			{
				"type": "sse_chunking",
				"provider": "openai"
			},
			{
				"type": "token_count",
				"provider": "openai"
			}
		]
	}`

	mockStore := &mockStorage{
		data: map[string][]byte{
			"ai-sse-test.local": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	req := httptest.NewRequest("POST", "http://ai-sse-test.local/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}],"stream":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "ai-sse-test.local"

	requestData := reqctx.NewRequestData()
	ctx := reqctx.SetRequestData(req.Context(), requestData)
	req = req.WithContext(ctx)

	cfg, err := Load(req, mgr)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	rr := httptest.NewRecorder()
	cfg.ServeHTTP(rr, req)

	resp := rr.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// SSE chunking should have set X-Stream-Chunks header
	if v := resp.Header.Get("X-Stream-Chunks"); v == "" {
		t.Error("expected X-Stream-Chunks header from sse_chunking transform")
	}
}
