package config

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAIProxyInlineOrigin_ChatCompletion(t *testing.T) {
	// Create a mock OpenAI-compatible server
	mockCalled := false
	var mockReqBody []byte
	var mockAuthHeader string

	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mockCalled = true
		mockAuthHeader = r.Header.Get("Authorization")
		mockReqBody, _ = io.ReadAll(r.Body)

		t.Logf("Mock received: %s %s", r.Method, r.URL.Path)
		t.Logf("Mock auth: %s", mockAuthHeader)
		t.Logf("Mock body: %s", string(mockReqBody))

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"id": "chatcmpl-test-123",
			"object": "chat.completion",
			"created": 1700000000,
			"model": "gpt-4o-mini",
			"choices": [{
				"index": 0,
				"message": {"role": "assistant", "content": "Hello from mock!"},
				"finish_reason": "stop"
			}],
			"usage": {
				"prompt_tokens": 5,
				"completion_tokens": 3,
				"total_tokens": 8
			}
		}`))
	}))
	defer mock.Close()

	// Create the AI proxy config JSON
	configJSON := []byte(`{
		"id": "ai-test",
		"hostname": "test.local",
		"workspace_id": "test",
		"version": "1.0.0",
		"action": {
			"type": "ai_proxy",
			"providers": [{
				"name": "mock",
				"type": "openai",
				"api_key": "test-key-abc",
				"base_url": "` + mock.URL + `"
			}],
			"default_model": "gpt-4o-mini"
		}
	}`)

	// Load the config
	cfg, err := Load(configJSON)
	if err != nil {
		t.Fatalf("Load config failed: %v", err)
	}

	// Create a request
	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Host", "test.local")

	// Serve the request
	w := httptest.NewRecorder()
	cfg.ServeHTTP(w, req)

	resp := w.Result()
	respBody, _ := io.ReadAll(resp.Body)

	t.Logf("Response status: %d", resp.StatusCode)
	t.Logf("Response body: %s", string(respBody))

	// Verify mock was called
	if !mockCalled {
		t.Fatal("Mock server was not called")
	}

	// Verify auth header was injected
	if mockAuthHeader != "Bearer test-key-abc" {
		t.Errorf("Expected auth header 'Bearer test-key-abc', got '%s'", mockAuthHeader)
	}

	// Verify response
	if resp.StatusCode != 200 {
		t.Errorf("Expected 200, got %d", resp.StatusCode)
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	choices, ok := result["choices"].([]any)
	if !ok || len(choices) == 0 {
		t.Fatalf("Expected non-empty choices, got: %v", result["choices"])
	}

	choice := choices[0].(map[string]any)
	msg := choice["message"].(map[string]any)
	content := msg["content"].(string)
	if content != "Hello from mock!" {
		t.Errorf("Expected 'Hello from mock!', got '%s'", content)
	}
}
