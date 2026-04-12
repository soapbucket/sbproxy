package modifier

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestAISchemaValidation_OpenAI_Valid(t *testing.T) {
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}`
	req, _ := http.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	cfg := &AISchemaValidationConfig{Provider: "openai"}
	if err := applyAISchemaValidation(req, cfg); err != nil {
		t.Fatal(err)
	}

	// Should not set reject header
	if req.Header.Get("X-AI-Schema-Reject") != "" {
		t.Error("expected no reject header for valid request")
	}
}

func TestAISchemaValidation_OpenAI_MissingModel(t *testing.T) {
	body := `{"messages":[{"role":"user","content":"hello"}]}`
	req, _ := http.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	cfg := &AISchemaValidationConfig{Provider: "openai", Action: "reject"}
	if err := applyAISchemaValidation(req, cfg); err != nil {
		t.Fatal(err)
	}

	if req.Header.Get("X-AI-Schema-Reject") != "400" {
		t.Errorf("expected reject header 400, got %q", req.Header.Get("X-AI-Schema-Reject"))
	}
	if !strings.Contains(req.Header.Get("X-AI-Schema-Errors"), "model") {
		t.Error("expected errors to mention 'model'")
	}
}

func TestAISchemaValidation_OpenAI_MissingMessages(t *testing.T) {
	body := `{"model":"gpt-4o"}`
	req, _ := http.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	cfg := &AISchemaValidationConfig{Provider: "openai"}
	if err := applyAISchemaValidation(req, cfg); err != nil {
		t.Fatal(err)
	}

	if req.Header.Get("X-AI-Schema-Reject") != "400" {
		t.Error("expected reject for missing messages")
	}
}

func TestAISchemaValidation_Anthropic_Valid(t *testing.T) {
	body := `{"model":"claude-sonnet-4-20250514","messages":[{"role":"user","content":"hi"}],"max_tokens":100}`
	req, _ := http.NewRequest("POST", "/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	cfg := &AISchemaValidationConfig{Provider: "anthropic"}
	if err := applyAISchemaValidation(req, cfg); err != nil {
		t.Fatal(err)
	}

	if req.Header.Get("X-AI-Schema-Reject") != "" {
		t.Error("expected no reject for valid Anthropic request")
	}
}

func TestAISchemaValidation_Anthropic_MissingMaxTokens(t *testing.T) {
	body := `{"model":"claude-sonnet-4-20250514","messages":[{"role":"user","content":"hi"}]}`
	req, _ := http.NewRequest("POST", "/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	cfg := &AISchemaValidationConfig{Provider: "anthropic"}
	if err := applyAISchemaValidation(req, cfg); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(req.Header.Get("X-AI-Schema-Errors"), "max_tokens") {
		t.Error("expected error mentioning max_tokens")
	}
}

func TestAISchemaValidation_WarnMode(t *testing.T) {
	body := `{"model":"gpt-4o"}` // missing messages
	req, _ := http.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	cfg := &AISchemaValidationConfig{Provider: "openai", Action: "warn"}
	if err := applyAISchemaValidation(req, cfg); err != nil {
		t.Fatal(err)
	}

	// Warn should not set reject header
	if req.Header.Get("X-AI-Schema-Reject") != "" {
		t.Error("warn mode should not set reject header")
	}
	if req.Header.Get("X-AI-Schema-Valid") != "false" {
		t.Error("expected X-AI-Schema-Valid: false in warn mode")
	}

	// Body should be preserved
	b, _ := io.ReadAll(req.Body)
	if string(b) != body {
		t.Errorf("body should be preserved in warn mode, got %q", string(b))
	}
}

func TestAISchemaValidation_CustomStatusCode(t *testing.T) {
	body := `{}`
	req, _ := http.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	cfg := &AISchemaValidationConfig{Provider: "openai", StatusCode: 422}
	if err := applyAISchemaValidation(req, cfg); err != nil {
		t.Fatal(err)
	}

	if req.Header.Get("X-AI-Schema-Reject") != "422" {
		t.Errorf("expected custom status 422, got %q", req.Header.Get("X-AI-Schema-Reject"))
	}
}

func TestAISchemaValidation_RequiredFields(t *testing.T) {
	body := `{"model":"gpt-4o","messages":[]}`
	req, _ := http.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	cfg := &AISchemaValidationConfig{
		Provider:       "openai",
		RequiredFields: []string{"temperature"},
	}
	if err := applyAISchemaValidation(req, cfg); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(req.Header.Get("X-AI-Schema-Errors"), "temperature") {
		t.Error("expected error about missing temperature field")
	}
}

func TestAISchemaValidation_SkipsNonJSON(t *testing.T) {
	body := `not json`
	req, _ := http.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	req.ContentLength = int64(len(body))

	cfg := &AISchemaValidationConfig{Provider: "openai"}
	if err := applyAISchemaValidation(req, cfg); err != nil {
		t.Fatal(err)
	}

	if req.Header.Get("X-AI-Schema-Reject") != "" {
		t.Error("should skip non-JSON content types")
	}
}

func TestAISchemaValidation_EmptyBody(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)

	cfg := &AISchemaValidationConfig{Provider: "openai"}
	if err := applyAISchemaValidation(req, cfg); err != nil {
		t.Fatal(err)
	}
	// Should not panic
}

func TestAISchemaValidation_Generic(t *testing.T) {
	body := `{"prompt":"hello"}`
	req, _ := http.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	cfg := &AISchemaValidationConfig{
		Provider:       "generic",
		RequiredFields: []string{"prompt"},
	}
	if err := applyAISchemaValidation(req, cfg); err != nil {
		t.Fatal(err)
	}

	if req.Header.Get("X-AI-Schema-Reject") != "" {
		t.Error("expected no reject for valid generic request")
	}
}
