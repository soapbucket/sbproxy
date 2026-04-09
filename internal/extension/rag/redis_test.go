package rag

import (
	"context"
	"encoding/binary"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	json "github.com/goccy/go-json"
	"github.com/redis/go-redis/v9"
)

func TestNewRedisProviderConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]string
		wantErr string
	}{
		{
			name:    "missing embedding_api_key",
			config:  map[string]string{"llm_api_key": "sk-llm"},
			wantErr: "embedding_api_key is required",
		},
		{
			name:    "missing llm_api_key",
			config:  map[string]string{"embedding_api_key": "sk-embed"},
			wantErr: "llm_api_key is required",
		},
		{
			name: "invalid embedding_dimensions",
			config: map[string]string{
				"embedding_api_key":    "sk-embed",
				"llm_api_key":          "sk-llm",
				"embedding_dimensions": "not-a-number",
			},
			wantErr: "invalid embedding_dimensions",
		},
		{
			name: "invalid redis_url",
			config: map[string]string{
				"embedding_api_key": "sk-embed",
				"llm_api_key":      "sk-llm",
				"redis_url":        "://bad-url",
			},
			wantErr: "invalid redis_url",
		},
		{
			name: "valid minimal config",
			config: map[string]string{
				"embedding_api_key": "sk-embed",
				"llm_api_key":      "sk-llm",
			},
			wantErr: "",
		},
		{
			name: "valid full config",
			config: map[string]string{
				"embedding_api_key":    "sk-embed",
				"llm_api_key":          "sk-llm",
				"redis_url":            "redis://localhost:6379/1",
				"index_name":           "my_index",
				"embedding_provider":   "openai",
				"embedding_model":      "text-embedding-3-large",
				"embedding_dimensions": "3072",
				"llm_provider":         "openai",
				"llm_model":            "gpt-4o",
				"llm_base_url":         "https://api.openai.com",
				"namespace":            "workspace-1",
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewRedisProvider(tt.config)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if p == nil {
					t.Fatal("expected non-nil provider")
				}
				// Clean up the Redis client (it won't actually connect).
				p.Close()
			}
		})
	}
}

func TestFloat32BytesRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		vec  []float32
	}{
		{
			name: "simple values",
			vec:  []float32{1.0, 2.0, 3.0, 4.0},
		},
		{
			name: "zero vector",
			vec:  []float32{0.0, 0.0, 0.0},
		},
		{
			name: "negative values",
			vec:  []float32{-1.5, -0.5, 0.5, 1.5},
		},
		{
			name: "small values",
			vec:  []float32{0.001, 0.002, 0.003},
		},
		{
			name: "single element",
			vec:  []float32{3.14},
		},
		{
			name: "empty vector",
			vec:  []float32{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bytes := float32ToBytes(tt.vec)

			// Verify byte length.
			if len(bytes) != len(tt.vec)*4 {
				t.Fatalf("got %d bytes, want %d", len(bytes), len(tt.vec)*4)
			}

			// Round-trip back.
			got := bytesToFloat32(bytes)
			if len(got) != len(tt.vec) {
				t.Fatalf("got %d floats, want %d", len(got), len(tt.vec))
			}

			for i := range tt.vec {
				if got[i] != tt.vec[i] {
					t.Errorf("index %d: got %f, want %f", i, got[i], tt.vec[i])
				}
			}
		})
	}
}

func TestFloat32ToBytesEncoding(t *testing.T) {
	// Verify little-endian encoding of a known float32 value.
	vec := []float32{1.0}
	bytes := float32ToBytes(vec)

	// float32(1.0) = 0x3F800000 in IEEE 754.
	// Little-endian: 00 00 80 3F.
	expected := make([]byte, 4)
	binary.LittleEndian.PutUint32(expected, math.Float32bits(1.0))

	for i := range expected {
		if bytes[i] != expected[i] {
			t.Errorf("byte %d: got %02x, want %02x", i, bytes[i], expected[i])
		}
	}
}

func TestParseFTSearchResult(t *testing.T) {
	tests := []struct {
		name       string
		raw        []interface{}
		wantCites  int
		wantChunks int
		wantErr    bool
	}{
		{
			name:       "empty results",
			raw:        []interface{}{int64(0)},
			wantCites:  0,
			wantChunks: 0,
		},
		{
			name: "single result",
			raw: []interface{}{
				int64(1),
				"ns:doc:d1:chunk:0",
				[]interface{}{
					"content", "This is the chunk content.",
					"doc_id", "d1",
					"doc_name", "test.pdf",
					"chunk_index", "0",
					"score", "0.15",
				},
			},
			wantCites:  1,
			wantChunks: 1,
		},
		{
			name: "multiple results",
			raw: []interface{}{
				int64(2),
				"ns:doc:d1:chunk:0",
				[]interface{}{
					"content", "First chunk content.",
					"doc_id", "d1",
					"doc_name", "a.pdf",
					"score", "0.1",
				},
				"ns:doc:d2:chunk:0",
				[]interface{}{
					"content", "Second chunk content.",
					"doc_id", "d2",
					"doc_name", "b.pdf",
					"score", "0.3",
				},
			},
			wantCites:  2,
			wantChunks: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build a mock redis.Cmd that returns our raw data.
			cmd := redis.NewCmd(context.Background())
			cmd.SetVal(tt.raw)

			citations, chunks, err := parseFTSearchResult(cmd)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(citations) != tt.wantCites {
				t.Errorf("got %d citations, want %d", len(citations), tt.wantCites)
			}
			if len(chunks) != tt.wantChunks {
				t.Errorf("got %d chunks, want %d", len(chunks), tt.wantChunks)
			}

			// Verify citation fields for single result.
			if tt.wantCites == 1 {
				c := citations[0]
				if c.DocumentID != "d1" {
					t.Errorf("doc_id: got %q, want %q", c.DocumentID, "d1")
				}
				if c.DocumentName != "test.pdf" {
					t.Errorf("doc_name: got %q, want %q", c.DocumentName, "test.pdf")
				}
				// Score should be 1.0 - 0.15 = 0.85 (cosine distance to similarity).
				if c.Score < 0.84 || c.Score > 0.86 {
					t.Errorf("score: got %f, want ~0.85", c.Score)
				}
			}
		})
	}
}

func TestBuildRAGSystemPrompt(t *testing.T) {
	chunks := []string{
		"The sky is blue.",
		"Water is wet.",
	}

	prompt := buildRAGSystemPrompt(chunks)

	// Verify the prompt contains the context marker and chunks.
	if !strings.Contains(prompt, "Context:") {
		t.Error("prompt missing 'Context:' marker")
	}
	if !strings.Contains(prompt, "[1] The sky is blue.") {
		t.Error("prompt missing chunk 1")
	}
	if !strings.Contains(prompt, "[2] Water is wet.") {
		t.Error("prompt missing chunk 2")
	}
	if !strings.Contains(prompt, "Use only the information from the context") {
		t.Error("prompt missing instruction to use context only")
	}
}

func TestLLMPromptConstruction(t *testing.T) {
	// Set up a mock LLM server that captures the request.
	var capturedReq chatCompletionRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&capturedReq); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		resp := chatCompletionResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{
				{Message: struct {
					Content string `json:"content"`
				}{Content: "The answer is 42."}},
			},
			Usage: struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
			}{PromptTokens: 50, CompletionTokens: 10},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	// Create a RedisProvider with mock LLM client.
	p := &RedisProvider{
		llmClient: NewHTTPClient(srv.URL),
		llmModel:  "gpt-4o-mini",
		namespace: "test",
	}

	chunks := []string{"Relevant context 1.", "Relevant context 2."}
	qopts := DefaultQueryOptions()
	qopts.MaxTokens = 100
	qopts.Temperature = 0.5

	answer, tokensIn, tokensOut, err := p.generateAnswer(
		context.Background(), "What is the answer?", chunks, "gpt-4o-mini", qopts,
	)
	if err != nil {
		t.Fatalf("generateAnswer: %v", err)
	}

	if answer != "The answer is 42." {
		t.Errorf("answer: got %q", answer)
	}
	if tokensIn != 50 {
		t.Errorf("tokensIn: got %d, want 50", tokensIn)
	}
	if tokensOut != 10 {
		t.Errorf("tokensOut: got %d, want 10", tokensOut)
	}

	// Verify the request sent to the LLM.
	if capturedReq.Model != "gpt-4o-mini" {
		t.Errorf("model: got %q", capturedReq.Model)
	}
	if len(capturedReq.Messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(capturedReq.Messages))
	}
	if capturedReq.Messages[0].Role != "system" {
		t.Errorf("message 0 role: got %q", capturedReq.Messages[0].Role)
	}
	if capturedReq.Messages[1].Role != "user" {
		t.Errorf("message 1 role: got %q", capturedReq.Messages[1].Role)
	}
	if capturedReq.Messages[1].Content != "What is the answer?" {
		t.Errorf("user message: got %q", capturedReq.Messages[1].Content)
	}
	if capturedReq.MaxTokens != 100 {
		t.Errorf("max_tokens: got %d, want 100", capturedReq.MaxTokens)
	}
	if capturedReq.Temperature != 0.5 {
		t.Errorf("temperature: got %f, want 0.5", capturedReq.Temperature)
	}
}

func TestRedisProviderName(t *testing.T) {
	p := &RedisProvider{}
	if p.Name() != "redis" {
		t.Errorf("Name(): got %q, want %q", p.Name(), "redis")
	}
}

func TestTruncateSnippet(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		maxWords int
		want     string
	}{
		{
			name:     "short text unchanged",
			text:     "hello world",
			maxWords: 10,
			want:     "hello world",
		},
		{
			name:     "long text truncated",
			text:     "one two three four five six",
			maxWords: 3,
			want:     "one two three...",
		},
		{
			name:     "exact boundary unchanged",
			text:     "a b c",
			maxWords: 3,
			want:     "a b c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateSnippet(tt.text, tt.maxWords)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConfigOrDefault(t *testing.T) {
	config := map[string]string{
		"key1": "value1",
		"key2": "",
	}

	tests := []struct {
		key        string
		defaultVal string
		want       string
	}{
		{"key1", "default", "value1"},
		{"key2", "default", "default"},       // empty string uses default
		{"key3", "fallback", "fallback"},      // missing key uses default
	}

	for _, tt := range tests {
		got := configOrDefault(config, tt.key, tt.defaultVal)
		if got != tt.want {
			t.Errorf("configOrDefault(%q, %q): got %q, want %q", tt.key, tt.defaultVal, got, tt.want)
		}
	}
}

func TestGenerateAnswerEmptyChunks(t *testing.T) {
	p := &RedisProvider{
		llmModel: "gpt-4o-mini",
	}

	answer, tokensIn, tokensOut, err := p.generateAnswer(
		context.Background(), "question", nil, "model", DefaultQueryOptions(),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(answer, "No relevant documents") {
		t.Errorf("expected 'no relevant documents' message, got %q", answer)
	}
	if tokensIn != 0 || tokensOut != 0 {
		t.Errorf("expected zero tokens, got in=%d out=%d", tokensIn, tokensOut)
	}
}
