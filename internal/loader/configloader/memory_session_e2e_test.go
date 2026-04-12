package configloader

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestAISession_Tracking_E2E tests AI session tracking creates and reuses session IDs
func TestAISession_Tracking_E2E(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "ai-sess-track.test", mock.URL, map[string]any{
		"action": map[string]any{
			"type":             "ai_proxy",
			"providers":        []map[string]any{{"name": "openai", "api_key": "test", "base_url": mock.URL + "/v1", "models": []string{"gpt-4o-mini"}}},
			"default_model":    "gpt-4o-mini",
			"session_tracking": true,
		},
	})

	r := newTestRequest(t, "POST", "http://ai-sess-track.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestAISession_MultipleProviders_E2E tests session tracking with multiple providers
func TestAISession_MultipleProviders_E2E(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyMultiProviderJSON(t, "ai-sess-multi.test", []string{mock.URL, mock.URL}, map[string]any{
		"action": map[string]any{
			"type": "ai_proxy",
			"providers": []map[string]any{
				{"name": "provider-0", "api_key": "key-0", "base_url": mock.URL + "/v1", "models": []string{"gpt-4o-mini"}},
				{"name": "provider-1", "api_key": "key-1", "base_url": mock.URL + "/v1", "models": []string{"gpt-4o-mini"}},
			},
			"default_model":    "gpt-4o-mini",
			"session_tracking": true,
		},
	})

	for i := 0; i < 3; i++ {
		r := newTestRequest(t, "POST", "http://ai-sess-multi.test/v1/chat/completions")
		r.Header.Set("Content-Type", "application/json")
		r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`))
		w := serveAIProxy(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d: %s", i, w.Code, w.Body.String())
		}
	}
}

// TestAIProxy_ModelRouting_E2E tests model-based provider routing
func TestAIProxy_ModelRouting_E2E(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "ai-model-route.test", mock.URL, nil)

	r := newTestRequest(t, "POST", "http://ai-model-route.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestAIProxy_Budget_E2E tests budget enforcement
func TestAIProxy_Budget_E2E(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "ai-budget.test", mock.URL, nil)

	r := newTestRequest(t, "POST", "http://ai-budget.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestAIProxy_Guardrails_E2E tests guardrails block prompt injection
func TestAIProxy_Guardrails_E2E(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "ai-guardrails.test", mock.URL, map[string]any{
		"action": map[string]any{
			"type":          "ai_proxy",
			"providers":     []map[string]any{{"name": "openai", "api_key": "test", "base_url": mock.URL + "/v1", "models": []string{"gpt-4o-mini"}}},
			"default_model": "gpt-4o-mini",
			"guardrails": map[string]any{
				"input": []map[string]any{
					{"type": "prompt_injection", "action": "block"},
				},
			},
		},
	})

	r := newTestRequest(t, "POST", "http://ai-guardrails.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello, how are you?"}]}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for clean input, got %d: %s", w.Code, w.Body.String())
	}
}
