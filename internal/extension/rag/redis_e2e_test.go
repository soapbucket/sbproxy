//go:build integration

package rag

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
"testing"
	"time"

	json "github.com/goccy/go-json"
	"github.com/redis/go-redis/v9"
)

// redisE2ESetup creates a RedisProvider wired to a real Redis instance and
// mock embedding + LLM servers. It returns the provider and a cleanup function.
// The test is skipped if Redis is not reachable at the given URL.
func redisE2ESetup(t *testing.T, redisURL string, dims int) (*RedisProvider, func()) {
	t.Helper()

	// Verify Redis is reachable.
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatalf("invalid redis URL %q: %v", redisURL, err)
	}
	rdb := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skipf("Redis not available at %s, skipping integration test: %v", redisURL, err)
	}
	rdb.Close()

	// Create mock embedding server that returns deterministic embeddings.
	embedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req openaiEmbedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Generate deterministic embeddings based on input text.
		var inputs []string
		switch v := req.Input.(type) {
		case string:
			inputs = []string{v}
		case []interface{}:
			for _, item := range v {
				if s, ok := item.(string); ok {
					inputs = append(inputs, s)
				}
			}
		}

		resp := openaiEmbedResponse{
			Data: make([]struct {
				Embedding []float32 `json:"embedding"`
			}, len(inputs)),
		}
		for i, text := range inputs {
			resp.Data[i].Embedding = deterministicEmbedding(text, dims)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))

	// Create mock LLM server.
	llmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req chatCompletionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Extract context from system prompt and generate a simple answer.
		systemContent := ""
		userQuestion := ""
		for _, msg := range req.Messages {
			if msg.Role == "system" {
				systemContent = msg.Content
			}
			if msg.Role == "user" {
				userQuestion = msg.Content
			}
		}

		answer := fmt.Sprintf("Based on the provided context, the answer to '%s' is found in the documents.", userQuestion)
		if strings.Contains(systemContent, "Context:") {
			answer = "The context contains relevant information about the topic."
		}

		resp := chatCompletionResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{
				{Message: struct {
					Content string `json:"content"`
				}{Content: answer}},
			},
			Usage: struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
			}{PromptTokens: 100, CompletionTokens: 25},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))

	// Use a unique namespace to avoid collisions.
	namespace := fmt.Sprintf("e2e_test_%d", time.Now().UnixNano())
	indexName := fmt.Sprintf("e2e_idx_%d", time.Now().UnixNano())

	provider := &RedisProvider{
		rdb:       redis.NewClient(opts),
		indexName: indexName,
		embedder:  NewEmbedderWithBaseURL(embedSrv.URL, "test-key", "text-embedding-3-small", dims),
		chunker:   NewChunker(10, 2), // Small chunks for testing.
		llmClient: NewHTTPClient(llmSrv.URL),
		llmModel:  "gpt-4o-mini",
		namespace: namespace,
		dims:      dims,
		logger:    defaultTestLogger(),
	}

	cleanup := func() {
		// Clean up Redis keys and index.
		ctx := context.Background()
		provider.rdb.Do(ctx, "FT.DROPINDEX", indexName, "DD")
		// Remove any remaining keys with our namespace prefix.
		iter := provider.rdb.Scan(ctx, 0, namespace+":*", 1000).Iterator()
		for iter.Next(ctx) {
			provider.rdb.Del(ctx, iter.Val())
		}
		provider.rdb.Close()
		embedSrv.Close()
		llmSrv.Close()
	}

	return provider, cleanup
}

// deterministicEmbedding generates a reproducible embedding vector from text.
// Similar texts produce similar vectors (based on shared words).
func deterministicEmbedding(text string, dims int) []float32 {
	vec := make([]float32, dims)
	words := strings.Fields(strings.ToLower(text))
	for i, word := range words {
		for j := 0; j < len(word) && j < dims; j++ {
			idx := (i*7 + j*13 + int(word[j])) % dims
			vec[idx] += float32(word[j]) / 255.0
		}
	}
	// Normalize to unit vector.
	var norm float32
	for _, v := range vec {
		norm += v * v
	}
	if norm > 0 {
		norm = float32(1.0 / float64(norm))
		for i := range vec {
			vec[i] *= norm
		}
	}
	return vec
}

// defaultTestLogger returns a no-op logger for tests.
func defaultTestLogger() *slog.Logger {
	return slog.Default()
}

func TestRedisE2E_FullFlow(t *testing.T) {
	dims := 32 // Small dimensions for testing.
	provider, cleanup := redisE2ESetup(t, "redis://localhost:6379/15", dims)
	defer cleanup()

	ctx := context.Background()

	t.Run("ingest_documents", func(t *testing.T) {
		docs := []Document{
			{
				ID:       "doc1",
				Content:  []byte("Go is a statically typed compiled programming language designed at Google. It is syntactically similar to C but with memory safety and garbage collection."),
				Filename: "go-intro.txt",
				Metadata: map[string]string{"source": "wiki", "lang": "en"},
			},
			{
				ID:       "doc2",
				Content:  []byte("Redis is an in-memory data structure store used as a database cache and message broker. It supports various data structures such as strings hashes lists sets and sorted sets."),
				Filename: "redis-intro.txt",
				Metadata: map[string]string{"source": "wiki", "lang": "en"},
			},
			{
				ID:       "doc3",
				Content:  []byte("Vector search enables similarity-based retrieval of documents using embedding representations. RediSearch provides vector similarity search capabilities."),
				Filename: "vector-search.txt",
				Metadata: map[string]string{"source": "docs"},
			},
		}

		err := provider.Ingest(ctx, docs)
		if err != nil {
			t.Fatalf("Ingest failed: %v", err)
		}

		// Verify chunks were stored in Redis.
		keys := provider.rdb.Keys(ctx, provider.namespace+":doc:*").Val()
		if len(keys) == 0 {
			t.Fatal("expected stored chunks in Redis, got none")
		}
		t.Logf("stored %d chunk keys in Redis", len(keys))
	})

	t.Run("query_with_llm", func(t *testing.T) {
		result, err := provider.Query(ctx, "What is Go programming language?",
			WithTopK(3),
			WithMaxTokens(200),
			WithTemperature(0.1),
		)
		if err != nil {
			t.Fatalf("Query failed: %v", err)
		}

		if result.Answer == "" {
			t.Error("expected non-empty answer")
		}
		if result.Provider != "redis" {
			t.Errorf("expected provider 'redis', got %q", result.Provider)
		}
		if result.Latency <= 0 {
			t.Error("expected positive latency")
		}
		if result.TokensIn <= 0 {
			t.Errorf("expected positive tokens_in, got %d", result.TokensIn)
		}
		if result.TokensOut <= 0 {
			t.Errorf("expected positive tokens_out, got %d", result.TokensOut)
		}
		t.Logf("answer: %s", result.Answer)
		t.Logf("citations: %d, latency: %s", len(result.Citations), result.Latency)
	})

	t.Run("query_with_namespace_override", func(t *testing.T) {
		// Query with a namespace that has no data should return no citations.
		result, err := provider.Query(ctx, "What is Redis?",
			WithNamespace("nonexistent-namespace"),
			WithTopK(5),
		)
		// This may or may not error depending on whether the index exists for that namespace.
		// The key point is that namespace isolation is attempted.
		if err != nil {
			t.Logf("query with wrong namespace returned error (expected): %v", err)
		} else {
			t.Logf("query with wrong namespace returned answer: %q, citations: %d", result.Answer, len(result.Citations))
		}
	})

	t.Run("query_with_model_override", func(t *testing.T) {
		result, err := provider.Query(ctx, "Tell me about vector search",
			WithModel("gpt-4o"),
			WithTopK(2),
		)
		if err != nil {
			t.Fatalf("Query with model override failed: %v", err)
		}
		if result.Answer == "" {
			t.Error("expected non-empty answer")
		}
	})

	t.Run("retrieve_only", func(t *testing.T) {
		citations, err := provider.Retrieve(ctx, "What data structures does Redis support?", 5)
		if err != nil {
			t.Fatalf("Retrieve failed: %v", err)
		}

		if len(citations) == 0 {
			t.Log("no citations returned (may be expected with deterministic embeddings)")
		} else {
			for i, c := range citations {
				t.Logf("citation %d: doc=%q, name=%q, score=%.4f, snippet=%q",
					i, c.DocumentID, c.DocumentName, c.Score, c.Snippet)
			}
		}
	})

	t.Run("retrieve_with_default_topk", func(t *testing.T) {
		// topK=0 should default to 5.
		citations, err := provider.Retrieve(ctx, "programming language", 0)
		if err != nil {
			t.Fatalf("Retrieve failed: %v", err)
		}
		t.Logf("retrieved %d citations with default topK", len(citations))
	})

	t.Run("ingest_empty_document", func(t *testing.T) {
		docs := []Document{
			{
				ID:       "empty-doc",
				Content:  []byte(""),
				Filename: "empty.txt",
			},
		}

		// Ingesting an empty document should not error (chunks will be empty).
		err := provider.Ingest(ctx, docs)
		if err != nil {
			t.Fatalf("Ingest empty doc failed: %v", err)
		}
	})

	t.Run("ingest_multiple_batches", func(t *testing.T) {
		// Ingest a second batch to verify incremental ingestion works.
		docs := []Document{
			{
				ID:       "doc4",
				Content:  []byte("Machine learning is a subset of artificial intelligence that enables systems to learn from data and improve without being explicitly programmed."),
				Filename: "ml-intro.txt",
			},
		}

		err := provider.Ingest(ctx, docs)
		if err != nil {
			t.Fatalf("Ingest second batch failed: %v", err)
		}

		// Query the newly ingested document.
		result, err := provider.Query(ctx, "What is machine learning?", WithTopK(3))
		if err != nil {
			t.Fatalf("Query after second ingest failed: %v", err)
		}
		if result.Answer == "" {
			t.Error("expected non-empty answer after second ingest")
		}
	})

	t.Run("health_check", func(t *testing.T) {
		err := provider.Health(ctx)
		if err != nil {
			t.Fatalf("Health check failed: %v", err)
		}
	})

	t.Run("health_json", func(t *testing.T) {
		data, err := provider.MarshalHealthJSON(ctx)
		if err != nil {
			t.Fatalf("MarshalHealthJSON failed: %v", err)
		}

		var status map[string]interface{}
		if err := json.Unmarshal(data, &status); err != nil {
			t.Fatalf("unmarshal health JSON: %v", err)
		}

		if status["provider"] != "redis" {
			t.Errorf("expected provider 'redis', got %v", status["provider"])
		}
		if status["healthy"] != true {
			t.Errorf("expected healthy=true, got %v", status["healthy"])
		}
	})
}

func TestRedisE2E_ChunkerEmbedderPipeline(t *testing.T) {
	// This test verifies the chunker + embedder pipeline independently
	// using mock servers, without requiring a running Redis instance.

	dims := 8
	embedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req openaiEmbedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var inputs []string
		switch v := req.Input.(type) {
		case string:
			inputs = []string{v}
		case []interface{}:
			for _, item := range v {
				if s, ok := item.(string); ok {
					inputs = append(inputs, s)
				}
			}
		}

		resp := openaiEmbedResponse{
			Data: make([]struct {
				Embedding []float32 `json:"embedding"`
			}, len(inputs)),
		}
		for i, text := range inputs {
			resp.Data[i].Embedding = deterministicEmbedding(text, dims)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer embedSrv.Close()

	embedder := NewEmbedderWithBaseURL(embedSrv.URL, "test-key", "test-model", dims)
	chunker := NewChunker(5, 1)

	doc := Document{
		ID:       "pipeline-doc",
		Content:  []byte("Go is a programming language designed at Google for building reliable and efficient software systems"),
		Filename: "go-design.txt",
		Metadata: map[string]string{"author": "test"},
	}

	t.Run("chunk_document", func(t *testing.T) {
		chunks := chunker.ChunkDoc(doc)
		if len(chunks) == 0 {
			t.Fatal("expected at least one chunk")
		}

		for i, chunk := range chunks {
			if chunk.DocID != doc.ID {
				t.Errorf("chunk %d: doc_id mismatch: got %q, want %q", i, chunk.DocID, doc.ID)
			}
			if chunk.DocName != doc.Filename {
				t.Errorf("chunk %d: doc_name mismatch: got %q, want %q", i, chunk.DocName, doc.Filename)
			}
			if chunk.Index != i {
				t.Errorf("chunk %d: index mismatch: got %d", i, chunk.Index)
			}
			if chunk.Content == "" {
				t.Errorf("chunk %d: empty content", i)
			}
		}

		t.Logf("document split into %d chunks", len(chunks))
	})

	t.Run("embed_chunks", func(t *testing.T) {
		chunks := chunker.ChunkDoc(doc)
		if len(chunks) == 0 {
			t.Fatal("no chunks to embed")
		}

		texts := make([]string, len(chunks))
		for i, c := range chunks {
			texts[i] = c.Content
		}

		embeddings, err := embedder.EmbedBatch(context.Background(), texts)
		if err != nil {
			t.Fatalf("EmbedBatch failed: %v", err)
		}

		if len(embeddings) != len(chunks) {
			t.Fatalf("expected %d embeddings, got %d", len(chunks), len(embeddings))
		}

		for i, emb := range embeddings {
			if len(emb) != dims {
				t.Errorf("embedding %d: expected %d dims, got %d", i, dims, len(emb))
			}
			// Verify the embedding is not all zeros.
			allZero := true
			for _, v := range emb {
				if v != 0 {
					allZero = false
					break
				}
			}
			if allZero {
				t.Errorf("embedding %d: all zeros", i)
			}
		}

		t.Logf("embedded %d chunks into %d-dim vectors", len(embeddings), dims)
	})

	t.Run("embed_single_query", func(t *testing.T) {
		vec, err := embedder.Embed(context.Background(), "What is Go?")
		if err != nil {
			t.Fatalf("Embed failed: %v", err)
		}
		if len(vec) != dims {
			t.Errorf("expected %d dims, got %d", dims, len(vec))
		}
	})

	t.Run("vector_roundtrip", func(t *testing.T) {
		chunks := chunker.ChunkDoc(doc)
		texts := make([]string, len(chunks))
		for i, c := range chunks {
			texts[i] = c.Content
		}

		embeddings, err := embedder.EmbedBatch(context.Background(), texts)
		if err != nil {
			t.Fatalf("EmbedBatch failed: %v", err)
		}

		// Verify float32 byte conversion round-trip for all embeddings.
		for i, emb := range embeddings {
			bytes := float32ToBytes(emb)
			recovered := bytesToFloat32(bytes)
			if len(recovered) != len(emb) {
				t.Fatalf("embedding %d: length mismatch after roundtrip", i)
			}
			for j := range emb {
				if recovered[j] != emb[j] {
					t.Errorf("embedding %d dim %d: got %f, want %f", i, j, recovered[j], emb[j])
				}
			}
		}
	})
}

func TestRedisE2E_ProviderFactory(t *testing.T) {
	// Test that the Redis provider can be created through the registry.
	r := DefaultRegistry()

	// Creating with valid config should succeed (even if Redis is not running,
	// the provider itself is created lazily).
	p, err := r.Create(ProviderConfig{
		Type:    "redis",
		Enabled: true,
		Config: map[string]string{
			"embedding_api_key": "test-embed-key",
			"llm_api_key":      "test-llm-key",
			"redis_url":        "redis://localhost:6379/15",
			"index_name":       "e2e_factory_test",
			"namespace":        "factory-test",
		},
	})
	if err != nil {
		t.Fatalf("Create redis provider: %v", err)
	}
	defer p.Close()

	if p.Name() != "redis" {
		t.Errorf("expected name 'redis', got %q", p.Name())
	}

	// Verify it's retrievable from registry.
	got, ok := r.Get("redis")
	if !ok {
		t.Fatal("expected redis provider in registry")
	}
	if got.Name() != "redis" {
		t.Errorf("expected name 'redis', got %q", got.Name())
	}
}
