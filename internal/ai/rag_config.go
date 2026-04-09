// Package ai provides the AI gateway functionality including RAG injection.
package ai

import (
	"context"
	"fmt"
	"hash/fnv"
	"math"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/cache"
	"github.com/soapbucket/sbproxy/internal/request/classifier"
)

// RAGConfig holds the configuration for RAG injection at the gateway level.
type RAGConfig struct {
	Enabled           bool    `json:"enabled"`
	StoreType         string  `json:"store_type"`
	// VectorDB is an alias for StoreType. If both are set, VectorDB takes precedence.
	VectorDB          string  `json:"vector_db,omitempty"`
	Collection        string  `json:"collection"`
	TopK              int     `json:"top_k"`
	// MaxDocuments is an alias for TopK. If both are set, MaxDocuments takes precedence.
	MaxDocuments      int     `json:"max_documents,omitempty"`
	Threshold         float64 `json:"threshold"`
	// SimilarityThreshold is an alias for Threshold. If both are set, SimilarityThreshold takes precedence.
	SimilarityThreshold float64 `json:"similarity_threshold,omitempty"`
	InjectionMode     string  `json:"injection_mode"` // prepend, append, system
	ChunkTemplate     string  `json:"chunk_template"` // Mustache template
	Namespace         string  `json:"namespace"`
	EmbeddingProvider string  `json:"embedding_provider"`
	EmbeddingModel    string  `json:"embedding_model"`
	MaxChunkSize      int     `json:"max_chunk_size"`
	// DocumentsFile is the path to a JSON file containing pre-chunked documents to ingest at startup.
	DocumentsFile     string  `json:"documents_file,omitempty"`
}

// ResolvedVectorDB returns the effective vector DB type, preferring VectorDB over StoreType.
func (c *RAGConfig) ResolvedVectorDB() string {
	if c.VectorDB != "" {
		return c.VectorDB
	}
	return c.StoreType
}

// ResolvedTopK returns the effective max documents to retrieve, preferring MaxDocuments over TopK.
func (c *RAGConfig) ResolvedTopK() int {
	if c.MaxDocuments > 0 {
		return c.MaxDocuments
	}
	return c.TopK
}

// ResolvedThreshold returns the effective similarity threshold, preferring SimilarityThreshold over Threshold.
func (c *RAGConfig) ResolvedThreshold() float64 {
	if c.SimilarityThreshold > 0 {
		return c.SimilarityThreshold
	}
	return c.Threshold
}

// DefaultChunkTemplate is the default Mustache template for formatting RAG chunks.
const DefaultChunkTemplate = "Context:\n{{content}}"

// RAGChunk represents a retrieved document chunk for RAG injection.
type RAGChunk struct {
	ID       string            `json:"id"`
	Content  string            `json:"content"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Score    float64           `json:"score"`
	Source   string            `json:"source,omitempty"`
}

// RAGRetriever defines the interface for retrieving relevant chunks for RAG.
type RAGRetriever interface {
	// Retrieve fetches relevant chunks for the given query.
	Retrieve(ctx context.Context, query string, limit int, threshold float64) ([]RAGChunk, error)

	// Ingest stores chunks into the retrieval backend.
	Ingest(ctx context.Context, chunks []RAGChunk) error
}

// DefaultRAGRetriever wraps a cache.VectorStore to implement RAGRetriever.
// It uses a simple hash-based embedding for cases where no external embedding
// provider is configured. This is suitable for testing but not production use.
type DefaultRAGRetriever struct {
	store cache.VectorStore
	dims  int
}

// NewDefaultRAGRetriever creates a new DefaultRAGRetriever wrapping the given VectorStore.
func NewDefaultRAGRetriever(store cache.VectorStore) *DefaultRAGRetriever {
	return &DefaultRAGRetriever{
		store: store,
		dims:  128,
	}
}

// Retrieve searches the vector store for chunks similar to the query.
func (r *DefaultRAGRetriever) Retrieve(ctx context.Context, query string, limit int, threshold float64) ([]RAGChunk, error) {
	embedding := simpleEmbedding(query, r.dims)
	entries, err := r.store.Search(ctx, embedding, threshold, limit)
	if err != nil {
		return nil, err
	}

	chunks := make([]RAGChunk, len(entries))
	for i, entry := range entries {
		chunks[i] = RAGChunk{
			ID:      entry.Key,
			Content: string(entry.Response),
			Score:   entry.Similarity,
			Source:  entry.Namespace,
		}
	}
	return chunks, nil
}

// Ingest stores chunks into the vector store.
func (r *DefaultRAGRetriever) Ingest(ctx context.Context, chunks []RAGChunk) error {
	for _, chunk := range chunks {
		embedding := simpleEmbedding(chunk.Content, r.dims)
		entry := cache.VectorEntry{
			Key:       chunk.ID,
			Namespace: chunk.Source,
			Embedding: embedding,
			Response:  []byte(chunk.Content),
			Model:     "rag",
			CreatedAt: time.Now(),
			TTL:       24 * time.Hour,
		}
		if err := r.store.Store(ctx, entry); err != nil {
			return err
		}
	}
	return nil
}

// LocalRAGRetriever wraps a VectorStore with sidecar-based local embeddings
// from the classifier ManagedClient instead of hash-based simpleEmbedding.
type LocalRAGRetriever struct {
	store cache.VectorStore
	mc    *classifier.ManagedClient
}

// NewLocalRAGRetriever creates a LocalRAGRetriever that uses the classifier
// sidecar for generating embeddings.
func NewLocalRAGRetriever(store cache.VectorStore, mc *classifier.ManagedClient) *LocalRAGRetriever {
	return &LocalRAGRetriever{store: store, mc: mc}
}

// Retrieve searches the vector store using sidecar-generated embeddings.
func (r *LocalRAGRetriever) Retrieve(ctx context.Context, query string, limit int, threshold float64) ([]RAGChunk, error) {
	embedding, err := r.mc.EmbedOne(query)
	if err != nil {
		return nil, fmt.Errorf("local embedding for RAG query: %w", err)
	}

	entries, err := r.store.Search(ctx, embedding, threshold, limit)
	if err != nil {
		return nil, err
	}

	chunks := make([]RAGChunk, len(entries))
	for i, entry := range entries {
		chunks[i] = RAGChunk{
			ID:      entry.Key,
			Content: string(entry.Response),
			Score:   entry.Similarity,
			Source:  entry.Namespace,
		}
	}
	return chunks, nil
}

// Ingest stores chunks into the vector store using sidecar-generated embeddings.
func (r *LocalRAGRetriever) Ingest(ctx context.Context, chunks []RAGChunk) error {
	for _, chunk := range chunks {
		embedding, err := r.mc.EmbedOne(chunk.Content)
		if err != nil {
			return fmt.Errorf("local embedding for RAG ingest: %w", err)
		}
		entry := cache.VectorEntry{
			Key:       chunk.ID,
			Namespace: chunk.Source,
			Embedding: embedding,
			Response:  []byte(chunk.Content),
			Model:     "local",
			CreatedAt: time.Now(),
			TTL:       24 * time.Hour,
		}
		if err := r.store.Store(ctx, entry); err != nil {
			return err
		}
	}
	return nil
}

// simpleEmbedding generates a deterministic hash-based embedding vector from text.
// This is not production quality but provides a functional embedding for testing
// and cases where no external embedding provider is configured.
func simpleEmbedding(text string, dims int) []float32 {
	if dims <= 0 {
		dims = 128
	}
	embedding := make([]float32, dims)

	// Tokenize on whitespace and hash each token into embedding dimensions.
	words := strings.Fields(strings.ToLower(text))
	for _, word := range words {
		h := fnv.New64a()
		_, _ = h.Write([]byte(word))
		hash := h.Sum64()

		// Distribute the hash across multiple dimensions for better coverage.
		idx1 := int(hash % uint64(dims))
		idx2 := int((hash >> 16) % uint64(dims))
		idx3 := int((hash >> 32) % uint64(dims))

		embedding[idx1] += 1.0
		embedding[idx2] += 0.5
		embedding[idx3] += 0.25
	}

	// Normalize to unit vector.
	var norm float64
	for _, v := range embedding {
		norm += float64(v) * float64(v)
	}
	if norm > 0 {
		norm = math.Sqrt(norm)
		for i := range embedding {
			embedding[i] = float32(float64(embedding[i]) / norm)
		}
	}

	return embedding
}
