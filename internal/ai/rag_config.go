// Package ai provides the AI gateway functionality including RAG injection.
package ai

import (
	"context"
)

// RAGConfig holds the configuration for RAG injection at the gateway level.
type RAGConfig struct {
	Enabled             bool    `json:"enabled"`
	StoreType           string  `json:"store_type"`
	VectorDB            string  `json:"vector_db,omitempty"`
	Collection          string  `json:"collection"`
	TopK                int     `json:"top_k"`
	MaxDocuments        int     `json:"max_documents,omitempty"`
	Threshold           float64 `json:"threshold"`
	SimilarityThreshold float64 `json:"similarity_threshold,omitempty"`
	InjectionMode       string  `json:"injection_mode"`
	ChunkTemplate       string  `json:"chunk_template"`
	Namespace           string  `json:"namespace"`
	EmbeddingProvider   string  `json:"embedding_provider"`
	EmbeddingModel      string  `json:"embedding_model"`
	MaxChunkSize        int     `json:"max_chunk_size"`
	DocumentsFile       string  `json:"documents_file,omitempty"`
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
	Retrieve(ctx context.Context, query string, limit int, threshold float64) ([]RAGChunk, error)
	Ingest(ctx context.Context, chunks []RAGChunk) error
}
