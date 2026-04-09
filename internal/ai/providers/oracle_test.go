package providers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func TestOracleProvider(t *testing.T) {
	cfg := &ai.ProviderConfig{Name: "oracle", Type: "oracle"}
	p, err := ai.NewProvider(cfg, http.DefaultClient)
	if err != nil {
		t.Fatalf("failed to create oracle provider: %v", err)
	}
	if p.Name() != "oracle" {
		t.Errorf("expected name 'oracle', got %q", p.Name())
	}
	if !p.SupportsStreaming() {
		t.Error("expected streaming support")
	}
	if !p.SupportsEmbeddings() {
		t.Error("expected embeddings support")
	}
}

func TestOracle_ChatCompletion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Bearer auth header.
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer oci-session-token-123" {
			t.Errorf("expected 'Bearer oci-session-token-123', got %q", authHeader)
		}

		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			t.Errorf("expected path ending in /chat/completions, got %s", r.URL.Path)
		}

		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		json.Unmarshal(body, &req)

		if req["model"] != "cohere.command-r-plus" {
			t.Errorf("expected model 'cohere.command-r-plus', got %v", req["model"])
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ai.ChatCompletionResponse{
			ID:     "chatcmpl-oracle-1",
			Object: "chat.completion",
			Model:  "cohere.command-r-plus",
			Choices: []ai.Choice{{
				Index:        0,
				Message:      ai.Message{Role: "assistant", Content: mustJSON("Hello from Oracle GenAI!")},
				FinishReason: strPtr("stop"),
			}},
			Usage: &ai.Usage{PromptTokens: 12, CompletionTokens: 6, TotalTokens: 18},
		})
	}))
	defer server.Close()

	p := NewOracle(server.Client())
	cfg := &ai.ProviderConfig{
		Name:    "oracle",
		APIKey:  "oci-session-token-123",
		BaseURL: server.URL,
	}

	resp, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model: "cohere.command-r-plus",
		Messages: []ai.Message{
			{Role: "system", Content: mustJSON("You are helpful.")},
			{Role: "user", Content: mustJSON("Hi there")},
		},
	}, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ID != "chatcmpl-oracle-1" {
		t.Errorf("expected ID 'chatcmpl-oracle-1', got %q", resp.ID)
	}
	if len(resp.Choices) != 1 {
		t.Fatalf("expected 1 choice, got %d", len(resp.Choices))
	}
	if resp.Choices[0].Message.Role != "assistant" {
		t.Errorf("expected role 'assistant', got %q", resp.Choices[0].Message.Role)
	}
	if resp.Choices[0].FinishReason == nil || *resp.Choices[0].FinishReason != "stop" {
		t.Errorf("expected finish reason 'stop', got %v", resp.Choices[0].FinishReason)
	}
	if resp.Usage == nil {
		t.Fatal("expected usage, got nil")
	}
	if resp.Usage.PromptTokens != 12 {
		t.Errorf("expected 12 prompt tokens, got %d", resp.Usage.PromptTokens)
	}
	if resp.Usage.CompletionTokens != 6 {
		t.Errorf("expected 6 completion tokens, got %d", resp.Usage.CompletionTokens)
	}
	if resp.Usage.TotalTokens != 18 {
		t.Errorf("expected 18 total tokens, got %d", resp.Usage.TotalTokens)
	}
}

func TestOracle_ErrorHandling(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
	}{
		{
			name:       "bad request",
			statusCode: http.StatusBadRequest,
			body:       `{"error":{"message":"invalid request body","type":"invalid_request_error"}}`,
		},
		{
			name:       "not found",
			statusCode: http.StatusNotFound,
			body:       `{"error":{"message":"model not found","type":"not_found"}}`,
		},
		{
			name:       "rate limited",
			statusCode: http.StatusTooManyRequests,
			body:       `{"error":{"message":"rate limit exceeded","type":"rate_limit_error"}}`,
		},
		{
			name:       "internal server error",
			statusCode: http.StatusInternalServerError,
			body:       `{"error":{"message":"internal error","type":"server_error"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.body))
			}))
			defer server.Close()

			p := NewOracle(server.Client())
			cfg := &ai.ProviderConfig{
				Name:    "oracle",
				APIKey:  "test-token",
				BaseURL: server.URL,
			}

			_, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
				Model:    "test-model",
				Messages: []ai.Message{{Role: "user", Content: mustJSON("Hi")}},
			}, cfg)

			if err == nil {
				t.Fatal("expected error, got nil")
			}
			aiErr, ok := err.(*ai.AIError)
			if !ok {
				t.Fatalf("expected *ai.AIError, got %T: %v", err, err)
			}
			if aiErr.StatusCode != tt.statusCode {
				t.Errorf("expected status %d, got %d", tt.statusCode, aiErr.StatusCode)
			}
		})
	}
}

func TestOracle_Embeddings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer embed-token" {
			t.Errorf("expected 'Bearer embed-token', got %q", authHeader)
		}

		if !strings.HasSuffix(r.URL.Path, "/embeddings") {
			t.Errorf("expected path ending in /embeddings, got %s", r.URL.Path)
		}

		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		json.Unmarshal(body, &req)
		if req["model"] != "cohere.embed-english-light-v3.0" {
			t.Errorf("expected model 'cohere.embed-english-light-v3.0', got %v", req["model"])
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ai.EmbeddingResponse{
			Object: "list",
			Data: []ai.EmbeddingData{{
				Object:    "embedding",
				Embedding: []float32{0.5, 0.6, 0.7, 0.8},
				Index:     0,
			}},
			Model: "cohere.embed-english-light-v3.0",
			Usage: &ai.EmbeddingUsage{PromptTokens: 2, TotalTokens: 2},
		})
	}))
	defer server.Close()

	p := NewOracle(server.Client())
	cfg := &ai.ProviderConfig{
		Name:    "oracle",
		APIKey:  "embed-token",
		BaseURL: server.URL,
	}

	resp, err := p.Embeddings(t.Context(), &ai.EmbeddingRequest{
		Input: "test embedding",
		Model: "cohere.embed-english-light-v3.0",
	}, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Object != "list" {
		t.Errorf("expected object 'list', got %q", resp.Object)
	}
	if len(resp.Data) != 1 {
		t.Fatalf("expected 1 embedding, got %d", len(resp.Data))
	}
	if len(resp.Data[0].Embedding) != 4 {
		t.Errorf("expected 4-dim embedding, got %d", len(resp.Data[0].Embedding))
	}
	if resp.Usage == nil {
		t.Fatal("expected usage, got nil")
	}
	if resp.Usage.PromptTokens != 2 {
		t.Errorf("expected 2 prompt tokens, got %d", resp.Usage.PromptTokens)
	}
}

func TestOracle_ModelMapping(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		json.Unmarshal(body, &req)

		if req["model"] != "cohere.command-r-plus" {
			t.Errorf("expected mapped model 'cohere.command-r-plus', got %v", req["model"])
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ai.ChatCompletionResponse{
			ID:      "chatcmpl-mapped",
			Object:  "chat.completion",
			Model:   "cohere.command-r-plus",
			Choices: []ai.Choice{{Index: 0, Message: ai.Message{Role: "assistant", Content: mustJSON("mapped")}, FinishReason: strPtr("stop")}},
		})
	}))
	defer server.Close()

	p := NewOracle(server.Client())
	cfg := &ai.ProviderConfig{
		Name:     "oracle",
		APIKey:   "test-token",
		BaseURL:  server.URL,
		ModelMap: map[string]string{"gpt-4": "cohere.command-r-plus"},
	}

	resp, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: []ai.Message{{Role: "user", Content: mustJSON("Hi")}},
	}, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Model != "cohere.command-r-plus" {
		t.Errorf("expected model 'cohere.command-r-plus', got %q", resp.Model)
	}
}

func TestOracle_InheritsGenericBehavior(t *testing.T) {
	// Verify that Oracle wraps Generic, which wraps OpenAI, so it inherits
	// standard OpenAI-compatible behavior. The Name() should be "oracle" even
	// though it delegates to Generic internally.
	p := NewOracle(http.DefaultClient)
	if p.Name() != "oracle" {
		t.Errorf("expected name 'oracle', got %q", p.Name())
	}
	if !p.SupportsStreaming() {
		t.Error("Oracle should inherit streaming support from Generic/OpenAI")
	}
	if !p.SupportsEmbeddings() {
		t.Error("Oracle should inherit embeddings support from Generic/OpenAI")
	}
}
