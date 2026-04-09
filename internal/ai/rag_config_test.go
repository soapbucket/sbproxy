package ai

import (
	"context"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/cache"
)

func TestDefaultRAGRetriever_IngestAndRetrieve(t *testing.T) {
	store := cache.NewMemoryVectorStore(100)
	retriever := NewDefaultRAGRetriever(store)
	ctx := context.Background()

	// Ingest some chunks.
	chunks := []RAGChunk{
		{ID: "doc1", Content: "Go is a statically typed compiled language.", Source: "docs"},
		{ID: "doc2", Content: "Python is an interpreted high-level language.", Source: "docs"},
		{ID: "doc3", Content: "Go supports concurrency with goroutines.", Source: "docs"},
	}

	if err := retriever.Ingest(ctx, chunks); err != nil {
		t.Fatalf("Ingest() error = %v", err)
	}

	// Verify store has entries.
	size, err := store.Size(ctx)
	if err != nil {
		t.Fatalf("Size() error = %v", err)
	}
	if size != 3 {
		t.Errorf("store size = %d, want 3", size)
	}

	// Retrieve with a query similar to Go content.
	results, err := retriever.Retrieve(ctx, "Go language concurrency", 5, 0.1)
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}

	if len(results) == 0 {
		t.Fatal("expected at least 1 result")
	}

	// Results should contain Go-related documents.
	foundGo := false
	for _, r := range results {
		if r.ID == "doc1" || r.ID == "doc3" {
			foundGo = true
			break
		}
	}
	if !foundGo {
		t.Error("expected Go-related document in results")
	}
}

func TestDefaultRAGRetriever_EmptyStore(t *testing.T) {
	store := cache.NewMemoryVectorStore(100)
	retriever := NewDefaultRAGRetriever(store)
	ctx := context.Background()

	results, err := retriever.Retrieve(ctx, "anything", 5, 0.1)
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestSimpleEmbedding(t *testing.T) {
	tests := []struct {
		name string
		text string
		dims int
	}{
		{name: "basic text", text: "hello world", dims: 128},
		{name: "empty text", text: "", dims: 128},
		{name: "single word", text: "test", dims: 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			emb := simpleEmbedding(tt.text, tt.dims)
			if len(emb) != tt.dims {
				t.Errorf("len(embedding) = %d, want %d", len(emb), tt.dims)
			}
		})
	}

	// Verify determinism.
	t.Run("deterministic", func(t *testing.T) {
		emb1 := simpleEmbedding("hello world", 128)
		emb2 := simpleEmbedding("hello world", 128)
		for i := range emb1 {
			if emb1[i] != emb2[i] {
				t.Fatalf("embedding not deterministic at index %d: %f != %f", i, emb1[i], emb2[i])
			}
		}
	})

	// Verify different texts produce different embeddings.
	t.Run("different texts differ", func(t *testing.T) {
		emb1 := simpleEmbedding("hello world", 128)
		emb2 := simpleEmbedding("completely different text", 128)
		same := true
		for i := range emb1 {
			if emb1[i] != emb2[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("expected different embeddings for different texts")
		}
	})
}

func TestRAGConfig_Defaults(t *testing.T) {
	config := &RAGConfig{}

	if config.TopK != 0 {
		t.Errorf("default TopK = %d, want 0 (pipeline applies default)", config.TopK)
	}
	if config.InjectionMode != "" {
		t.Errorf("default InjectionMode = %q, want empty (pipeline applies default)", config.InjectionMode)
	}
	if config.ChunkTemplate != "" {
		t.Errorf("default ChunkTemplate = %q, want empty (pipeline applies default)", config.ChunkTemplate)
	}
}

func TestRAGConfig_ResolvedVectorDB(t *testing.T) {
	// VectorDB takes precedence over StoreType.
	config := &RAGConfig{StoreType: "pinecone", VectorDB: "qdrant"}
	if got := config.ResolvedVectorDB(); got != "qdrant" {
		t.Errorf("ResolvedVectorDB() = %q, want %q", got, "qdrant")
	}

	// Falls back to StoreType when VectorDB is empty.
	config = &RAGConfig{StoreType: "pinecone"}
	if got := config.ResolvedVectorDB(); got != "pinecone" {
		t.Errorf("ResolvedVectorDB() = %q, want %q", got, "pinecone")
	}
}

func TestRAGConfig_ResolvedTopK(t *testing.T) {
	// MaxDocuments takes precedence over TopK.
	config := &RAGConfig{TopK: 5, MaxDocuments: 10}
	if got := config.ResolvedTopK(); got != 10 {
		t.Errorf("ResolvedTopK() = %d, want %d", got, 10)
	}

	// Falls back to TopK when MaxDocuments is 0.
	config = &RAGConfig{TopK: 5}
	if got := config.ResolvedTopK(); got != 5 {
		t.Errorf("ResolvedTopK() = %d, want %d", got, 5)
	}
}

func TestRAGConfig_ResolvedThreshold(t *testing.T) {
	// SimilarityThreshold takes precedence over Threshold.
	config := &RAGConfig{Threshold: 0.7, SimilarityThreshold: 0.85}
	if got := config.ResolvedThreshold(); got != 0.85 {
		t.Errorf("ResolvedThreshold() = %f, want %f", got, 0.85)
	}

	// Falls back to Threshold when SimilarityThreshold is 0.
	config = &RAGConfig{Threshold: 0.7}
	if got := config.ResolvedThreshold(); got != 0.7 {
		t.Errorf("ResolvedThreshold() = %f, want %f", got, 0.7)
	}
}

func TestDefaultChunkTemplate(t *testing.T) {
	if DefaultChunkTemplate == "" {
		t.Error("DefaultChunkTemplate should not be empty")
	}
}

func TestNewLocalRAGRetriever(t *testing.T) {
	store := cache.NewMemoryVectorStore(100)

	// With a nil ManagedClient, creation should succeed (error happens at use time).
	retriever := NewLocalRAGRetriever(store, nil)
	if retriever == nil {
		t.Fatal("NewLocalRAGRetriever returned nil")
	}
	if retriever.store == nil {
		t.Error("LocalRAGRetriever.store should not be nil")
	}
}

func TestLocalRAGRetriever_ImplementsInterface(t *testing.T) {
	store := cache.NewMemoryVectorStore(100)
	retriever := NewLocalRAGRetriever(store, nil)

	// Verify it satisfies RAGRetriever at compile time.
	var _ RAGRetriever = retriever
}

func TestNewDefaultRAGRetriever_StillWorks(t *testing.T) {
	store := cache.NewMemoryVectorStore(100)
	retriever := NewDefaultRAGRetriever(store)
	if retriever == nil {
		t.Fatal("NewDefaultRAGRetriever returned nil")
	}

	// Verify it still satisfies RAGRetriever.
	var _ RAGRetriever = retriever

	// Verify dims default.
	if retriever.dims != 128 {
		t.Errorf("dims = %d, want 128", retriever.dims)
	}
}
