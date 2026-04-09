// Package rag provides a unified interface for managed RAG (Retrieval-Augmented Generation)
// providers. It supports 8 managed cloud services (Pinecone Assistant, Vectara, AWS Bedrock KB,
// Google Vertex AI RAG, Ragie, Cloudflare AutoRAG, Nuclia, Cohere) and 1 local/self-hosted
// option (Redis with external embedding and LLM).
package rag

import (
	"context"
	"time"
)

// Document represents a source document for ingestion into a RAG provider.
type Document struct {
	ID       string            `json:"id"`
	Content  []byte            `json:"content"`
	Filename string            `json:"filename"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Citation tracks where an answer came from.
type Citation struct {
	DocumentID   string  `json:"document_id"`
	DocumentName string  `json:"document_name"`
	Snippet      string  `json:"snippet"`
	Pages        []int   `json:"pages,omitempty"`
	Score        float64 `json:"score"`
}

// QueryResult is the unified response from any RAG provider.
type QueryResult struct {
	Answer    string         `json:"answer"`
	Citations []Citation     `json:"citations,omitempty"`
	Provider  string         `json:"provider"`
	Latency   time.Duration  `json:"latency"`
	TokensIn  int            `json:"tokens_in"`
	TokensOut int            `json:"tokens_out"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// Provider is the common interface all RAG backends implement.
type Provider interface {
	// Name returns the provider identifier (e.g., "pinecone", "vectara", "redis").
	Name() string

	// Ingest uploads documents to the provider's knowledge base.
	Ingest(ctx context.Context, docs []Document) error

	// Query performs RAG retrieval + generation, returning an answer with citations.
	Query(ctx context.Context, question string, opts ...QueryOption) (*QueryResult, error)

	// Retrieve performs retrieval only (no generation), returning relevant citations.
	Retrieve(ctx context.Context, question string, topK int) ([]Citation, error)

	// Health checks provider connectivity and readiness.
	Health(ctx context.Context) error

	// Close cleans up resources (HTTP clients, connections, etc.).
	Close() error
}
