package modifier

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func TestTokenEstimation_OpenAI(t *testing.T) {
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"Hello, how are you doing today?"}]}`
	req, _ := http.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	cfg := &TokenEstimationConfig{Provider: "openai"}
	if err := applyTokenEstimation(req, cfg); err != nil {
		t.Fatal(err)
	}

	est := req.Header.Get("X-Estimated-Tokens")
	if est == "" {
		t.Fatal("expected X-Estimated-Tokens header")
	}

	tokens, _ := strconv.Atoi(est)
	if tokens <= 0 {
		t.Errorf("expected positive token count, got %d", tokens)
	}

	// Body should be preserved
	b, _ := io.ReadAll(req.Body)
	if len(b) != len(body) {
		t.Errorf("body length changed: %d vs %d", len(b), len(body))
	}
}

func TestTokenEstimation_Anthropic(t *testing.T) {
	body := `{"model":"claude-sonnet-4-20250514","messages":[{"role":"user","content":"Tell me about the weather"}],"system":"You are a helpful assistant"}`
	req, _ := http.NewRequest("POST", "/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	cfg := &TokenEstimationConfig{Provider: "anthropic"}
	if err := applyTokenEstimation(req, cfg); err != nil {
		t.Fatal(err)
	}

	est := req.Header.Get("X-Estimated-Tokens")
	if est == "" {
		t.Fatal("expected X-Estimated-Tokens header")
	}

	tokens, _ := strconv.Atoi(est)
	// Should include message tokens + system tokens
	if tokens < 5 {
		t.Errorf("expected reasonable token estimate, got %d", tokens)
	}
}

func TestTokenEstimation_MaxTokensBudget_Under(t *testing.T) {
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}`
	req, _ := http.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	cfg := &TokenEstimationConfig{Provider: "openai", MaxTokens: 10000}
	if err := applyTokenEstimation(req, cfg); err != nil {
		t.Fatal(err)
	}

	if req.Header.Get("X-Token-Budget-Exceeded") != "" {
		t.Error("should not exceed budget for small message")
	}
}

func TestTokenEstimation_MaxTokensBudget_Over(t *testing.T) {
	// Build a large message
	words := make([]string, 1000)
	for i := range words {
		words[i] = "word"
	}
	content := strings.Join(words, " ")
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"` + content + `"}]}`
	req, _ := http.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	cfg := &TokenEstimationConfig{Provider: "openai", MaxTokens: 10}
	if err := applyTokenEstimation(req, cfg); err != nil {
		t.Fatal(err)
	}

	if req.Header.Get("X-Token-Budget-Exceeded") != "true" {
		t.Error("expected budget exceeded for large message")
	}
	if req.Header.Get("X-Token-Budget-Reject") != "413" {
		t.Errorf("expected reject 413, got %q", req.Header.Get("X-Token-Budget-Reject"))
	}
}

func TestTokenEstimation_CustomHeader(t *testing.T) {
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"test"}]}`
	req, _ := http.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	cfg := &TokenEstimationConfig{Provider: "openai", HeaderPrefix: "X-My-Tokens"}
	if err := applyTokenEstimation(req, cfg); err != nil {
		t.Fatal(err)
	}

	if req.Header.Get("X-My-Tokens") == "" {
		t.Error("expected custom header prefix")
	}
	if req.Header.Get("X-Estimated-Tokens") != "" {
		t.Error("default header should not be set when custom is used")
	}
}

func TestTokenEstimation_NonJSON(t *testing.T) {
	req, _ := http.NewRequest("POST", "/", strings.NewReader("plain text"))
	req.Header.Set("Content-Type", "text/plain")
	req.ContentLength = 10

	cfg := &TokenEstimationConfig{Provider: "openai"}
	if err := applyTokenEstimation(req, cfg); err != nil {
		t.Fatal(err)
	}

	if req.Header.Get("X-Estimated-Tokens") != "" {
		t.Error("should skip non-JSON")
	}
}

func TestTokenEstimation_EmptyBody(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	cfg := &TokenEstimationConfig{Provider: "openai"}
	if err := applyTokenEstimation(req, cfg); err != nil {
		t.Fatal(err)
	}
	// Should not panic
}

func TestTokenEstimation_Generic(t *testing.T) {
	body := `{"prompt":"Tell me about the history of computing in detail"}`
	req, _ := http.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	cfg := &TokenEstimationConfig{Provider: "generic"}
	if err := applyTokenEstimation(req, cfg); err != nil {
		t.Fatal(err)
	}

	est := req.Header.Get("X-Estimated-Tokens")
	if est == "" {
		t.Fatal("expected token estimate for generic provider")
	}
	tokens, _ := strconv.Atoi(est)
	if tokens <= 0 {
		t.Errorf("expected positive token estimate, got %d", tokens)
	}
}

func TestEstimateTextTokens(t *testing.T) {
	tests := []struct {
		text      string
		minTokens int
	}{
		{"", 0},
		{"hello", 1},
		{"hello world how are you", 5},
	}

	for _, tt := range tests {
		tokens := estimateTextTokens(tt.text)
		if tokens < tt.minTokens {
			t.Errorf("estimateTextTokens(%q) = %d, want >= %d", tt.text, tokens, tt.minTokens)
		}
	}
}
