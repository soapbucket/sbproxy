package rag

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	json "github.com/goccy/go-json"
)

func TestEmbedOpenAI(t *testing.T) {
	wantEmbedding := []float32{0.1, 0.2, 0.3, 0.4}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/embeddings" {
			t.Errorf("expected /v1/embeddings, got %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("unexpected auth header: %s", r.Header.Get("Authorization"))
		}

		var req openaiEmbedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Model != "text-embedding-3-small" {
			t.Errorf("unexpected model: %s", req.Model)
		}

		resp := openaiEmbedResponse{
			Data: []struct {
				Embedding []float32 `json:"embedding"`
			}{
				{Embedding: wantEmbedding},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	embedder := NewEmbedderWithBaseURL(srv.URL, "test-key", "text-embedding-3-small", 4)

	got, err := embedder.Embed(context.Background(), "hello world")
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}

	if len(got) != len(wantEmbedding) {
		t.Fatalf("got %d dims, want %d", len(got), len(wantEmbedding))
	}
	for i := range wantEmbedding {
		if got[i] != wantEmbedding[i] {
			t.Errorf("dim %d: got %f, want %f", i, got[i], wantEmbedding[i])
		}
	}
}

func TestEmbedCohere(t *testing.T) {
	wantEmbedding := []float32{0.5, 0.6, 0.7}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/embed" {
			t.Errorf("expected /v2/embed, got %s", r.URL.Path)
		}

		var req cohereEmbedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.InputType != "search_query" {
			t.Errorf("unexpected input_type: %s", req.InputType)
		}
		if len(req.Texts) != 1 || req.Texts[0] != "test query" {
			t.Errorf("unexpected texts: %v", req.Texts)
		}

		resp := cohereEmbedResponse{}
		resp.Embeddings.Float = [][]float32{wantEmbedding}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	// Create a Cohere embedder pointing at our test server.
	embedder := &Embedder{
		client:     NewHTTPClient(srv.URL, WithBearerAuth("cohere-key")),
		model:      "embed-v3",
		dimensions: 3,
		provider:   "cohere",
	}

	got, err := embedder.Embed(context.Background(), "test query")
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}

	if len(got) != len(wantEmbedding) {
		t.Fatalf("got %d dims, want %d", len(got), len(wantEmbedding))
	}
	for i := range wantEmbedding {
		if got[i] != wantEmbedding[i] {
			t.Errorf("dim %d: got %f, want %f", i, got[i], wantEmbedding[i])
		}
	}
}

func TestEmbedErrorHandling(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
	}{
		{
			name:       "400 bad request",
			statusCode: 400,
			body:       `{"error":"invalid request"}`,
		},
		{
			name:       "401 unauthorized",
			statusCode: 401,
			body:       `{"error":"invalid api key"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			embedder := NewEmbedderWithBaseURL(srv.URL, "bad-key", "model", 4)
			_, err := embedder.Embed(context.Background(), "test")
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestEmbedBatchOpenAI(t *testing.T) {
	texts := []string{"hello", "world", "test"}
	wantEmbeddings := [][]float32{
		{0.1, 0.2},
		{0.3, 0.4},
		{0.5, 0.6},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req openaiEmbedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}

		// Input should be a slice of strings for batch.
		inputSlice, ok := req.Input.([]interface{})
		if !ok {
			t.Fatalf("expected []interface{} input, got %T", req.Input)
		}
		if len(inputSlice) != 3 {
			t.Fatalf("expected 3 inputs, got %d", len(inputSlice))
		}

		resp := openaiEmbedResponse{
			Data: make([]struct {
				Embedding []float32 `json:"embedding"`
			}, 3),
		}
		for i, emb := range wantEmbeddings {
			resp.Data[i].Embedding = emb
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	embedder := NewEmbedderWithBaseURL(srv.URL, "test-key", "model", 2)

	got, err := embedder.EmbedBatch(context.Background(), texts)
	if err != nil {
		t.Fatalf("EmbedBatch: %v", err)
	}

	if len(got) != len(wantEmbeddings) {
		t.Fatalf("got %d embeddings, want %d", len(got), len(wantEmbeddings))
	}

	for i := range wantEmbeddings {
		for j := range wantEmbeddings[i] {
			if got[i][j] != wantEmbeddings[i][j] {
				t.Errorf("embedding[%d][%d]: got %f, want %f", i, j, got[i][j], wantEmbeddings[i][j])
			}
		}
	}
}

func TestEmbedBatchCohere(t *testing.T) {
	texts := []string{"hello", "world"}
	wantEmbeddings := [][]float32{
		{0.1, 0.2, 0.3},
		{0.4, 0.5, 0.6},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req cohereEmbedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.InputType != "search_document" {
			t.Errorf("batch should use search_document input type, got %s", req.InputType)
		}
		if len(req.Texts) != 2 {
			t.Fatalf("expected 2 texts, got %d", len(req.Texts))
		}

		resp := cohereEmbedResponse{}
		resp.Embeddings.Float = wantEmbeddings
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	embedder := &Embedder{
		client:     NewHTTPClient(srv.URL, WithBearerAuth("cohere-key")),
		model:      "embed-v3",
		dimensions: 3,
		provider:   "cohere",
	}

	got, err := embedder.EmbedBatch(context.Background(), texts)
	if err != nil {
		t.Fatalf("EmbedBatch: %v", err)
	}

	if len(got) != len(wantEmbeddings) {
		t.Fatalf("got %d embeddings, want %d", len(got), len(wantEmbeddings))
	}

	for i := range wantEmbeddings {
		for j := range wantEmbeddings[i] {
			if got[i][j] != wantEmbeddings[i][j] {
				t.Errorf("embedding[%d][%d]: got %f, want %f", i, j, got[i][j], wantEmbeddings[i][j])
			}
		}
	}
}

func TestEmbedBatchEmpty(t *testing.T) {
	embedder := NewEmbedder("openai", "key", "model", 4)
	got, err := embedder.EmbedBatch(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}
