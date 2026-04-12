package configloader

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestCELModelSelector_E2E verifies CEL model_selector routes based on prompt content
func TestCELModelSelector_E2E(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "cel-model.test", mock.URL, nil)

	r := newTestRequest(t, "POST", "http://cel-model.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestLuaRequestHook_SystemPromptInjection_E2E verifies Lua on_request hook runs and enriches data
func TestLuaRequestHook_SystemPromptInjection_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "lua-req-hook.test",
		"action":   map[string]any{"type": "echo"},
		"on_request": []map[string]any{
			{
				"lua_script": `function match_request(req, ctx)
					return {injected = "system-prompt"}
				end`,
				"variable_name": "lua_result",
			},
		},
	})

	r := newTestRequest(t, "GET", "http://lua-req-hook.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestLuaResponseHook_StripThinking_E2E verifies Lua on_response callback runs
func TestLuaResponseHook_StripThinking_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "lua-resp-hook.test",
		"action": map[string]any{
			"type":        "mock",
			"status_code": 200,
			"body":        `{"text":"hello <think>internal</think> world"}`,
			"headers":     map[string]string{"Content-Type": "application/json"},
		},
		"on_response": []map[string]any{
			{
				"lua_script": `function match_request(req, ctx)
					return {processed = true}
				end`,
				"variable_name": "response_processed",
			},
		},
	})

	r := newTestRequest(t, "GET", "http://lua-resp-hook.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestCELGuardrailBlock_Injection_E2E verifies regex-based guardrail blocks prompt injection
func TestCELGuardrailBlock_Injection_E2E(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "cel-gr-block.test", mock.URL, map[string]any{
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

	r := newTestRequest(t, "POST", "http://cel-gr-block.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello, what is the weather?"}]}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for clean input, got %d: %s", w.Code, w.Body.String())
	}
}

// TestCELGuardrailFlag_LongOutput_E2E verifies length_limit guardrail flags long output
func TestCELGuardrailFlag_LongOutput_E2E(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "cel-gr-flag.test", mock.URL, map[string]any{
		"action": map[string]any{
			"type":          "ai_proxy",
			"providers":     []map[string]any{{"name": "openai", "api_key": "test", "base_url": mock.URL + "/v1", "models": []string{"gpt-4o-mini"}}},
			"default_model": "gpt-4o-mini",
			"guardrails": map[string]any{
				"output": []map[string]any{
					{"type": "length_limit", "action": "flag", "config": map[string]any{"max_length": 10000}},
				},
			},
		},
	})

	r := newTestRequest(t, "POST", "http://cel-gr-flag.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
