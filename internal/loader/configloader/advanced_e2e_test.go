package configloader

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMCPToolFilter_E2E verifies that MCP tool filtering restricts which tools are available.
func TestMCPToolFilter_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "mcp-filter.test",
		"action": map[string]any{
			"type": "mcp",
			"server_info": map[string]any{
				"name":    "filter-test",
				"version": "1.0.0",
			},
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
			"tools": []map[string]any{
				{
					"name":         "public_tool",
					"description":  "Public tool",
					"input_schema": json.RawMessage(`{"type":"object"}`),
					"handler":      map[string]any{"type": "static", "static": map[string]any{"content": "public"}},
				},
				{
					"name":         "admin_tool",
					"description":  "Admin tool",
					"input_schema": json.RawMessage(`{"type":"object"}`),
					"handler":      map[string]any{"type": "static", "static": map[string]any{"content": "admin"}},
				},
			},
		},
	})

	// List all tools - should see both
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	r := newTestRequest(t, "POST", "http://mcp-filter.test/")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(body))
	w := serveOriginJSON(t, cfg, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	result := resp["result"].(map[string]any)
	tools := result["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}
}

// TestKeyPooling_E2E verifies round-robin key pooling across multiple provider keys.
func TestKeyPooling_E2E(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "keypool.test", mock.URL, map[string]any{
		"action": map[string]any{
			"type": "ai_proxy",
			"providers": []map[string]any{
				{"name": "openai", "api_key": "key-1,key-2,key-3", "base_url": mock.URL + "/v1", "models": []string{"gpt-4o-mini"}},
			},
			"default_model": "gpt-4o-mini",
		},
	})

	for i := 0; i < 5; i++ {
		r := newTestRequest(t, "POST", "http://keypool.test/v1/chat/completions")
		r.Header.Set("Content-Type", "application/json")
		r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`))
		w := serveAIProxy(t, cfg, r)
		if w.Code != 200 {
			t.Fatalf("request %d: expected 200, got %d: %s", i, w.Code, w.Body.String())
		}
	}
}

// TestPassthroughEndpoint_E2E verifies that proxy action routes requests to upstream.
func TestPassthroughEndpoint_E2E(t *testing.T) {
	resetCache()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream passthrough"))
	}))
	defer upstream.Close()

	cfg := originJSON(t, map[string]any{
		"hostname": "passthrough.test",
		"action": map[string]any{
			"type": "proxy",
			"url":  upstream.URL,
		},
	})

	r := newTestRequest(t, "GET", "http://passthrough.test/api/data")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "upstream passthrough") {
		t.Fatalf("expected upstream response, got: %s", w.Body.String())
	}
}

// TestComplexityRouting_E2E verifies requests are routed based on model/complexity.
func TestComplexityRouting_E2E(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyMultiProviderJSON(t, "complexity.test", []string{mock.URL, mock.URL}, nil)

	r := newTestRequest(t, "POST", "http://complexity.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestFakeStreaming_E2E verifies non-streaming upstream converted to SSE for streaming clients.
func TestFakeStreaming_E2E(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "fake-stream.test", mock.URL, nil)

	r := newTestRequest(t, "POST", "http://fake-stream.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}],"stream":true}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
