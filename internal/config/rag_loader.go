package config

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/soapbucket/sbproxy/internal/ai"
	"github.com/soapbucket/sbproxy/internal/extension/rag"
)

// ragDocumentFile is the JSON structure for a RAG documents file.
type ragDocumentFile struct {
	Documents []ragDocumentEntry `json:"documents"`
}

// ragDocumentEntry represents a single pre-chunked document for RAG ingestion.
type ragDocumentEntry struct {
	ID       string            `json:"id"`
	Content  string            `json:"content"`
	Source   string            `json:"source,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// loadRAGDocuments reads a JSON file of pre-chunked documents and ingests them into the RAG retriever.
func loadRAGDocuments(retriever ai.RAGRetriever, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read documents file: %w", err)
	}

	var docFile ragDocumentFile
	if err := json.Unmarshal(data, &docFile); err != nil {
		return fmt.Errorf("parse documents file: %w", err)
	}

	if len(docFile.Documents) == 0 {
		slog.Info("RAG documents file is empty, no documents to ingest", "path", path)
		return nil
	}

	chunks := make([]ai.RAGChunk, len(docFile.Documents))
	for i, doc := range docFile.Documents {
		chunks[i] = ai.RAGChunk{
			ID:       doc.ID,
			Content:  doc.Content,
			Source:   doc.Source,
			Metadata: doc.Metadata,
		}
	}

	if err := retriever.Ingest(context.Background(), chunks); err != nil {
		return fmt.Errorf("ingest documents: %w", err)
	}

	slog.Info("loaded RAG documents from file", "path", path, "count", len(chunks))
	return nil
}

// ragProviderAdapter bridges the rag.Provider interface to the ai.RAGRetriever interface.
type ragProviderAdapter struct {
	provider rag.Provider
}

func (a *ragProviderAdapter) Retrieve(ctx context.Context, query string, limit int, threshold float64) ([]ai.RAGChunk, error) {
	citations, err := a.provider.Retrieve(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	chunks := make([]ai.RAGChunk, len(citations))
	for i, c := range citations {
		chunks[i] = ai.RAGChunk{
			ID:      c.DocumentID,
			Content: c.Snippet,
			Score:   c.Score,
			Source:  c.DocumentName,
		}
	}
	return chunks, nil
}

func (a *ragProviderAdapter) Ingest(ctx context.Context, chunks []ai.RAGChunk) error {
	docs := make([]rag.Document, len(chunks))
	for i, c := range chunks {
		docs[i] = rag.Document{
			ID:      c.ID,
			Content: []byte(c.Content),
		}
	}
	return a.provider.Ingest(ctx, docs)
}
