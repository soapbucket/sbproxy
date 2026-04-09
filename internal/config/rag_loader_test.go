package config

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai"
)

type mockRAGRetriever struct {
	ingested []ai.RAGChunk
}

func (m *mockRAGRetriever) Retrieve(_ context.Context, _ string, _ int, _ float64) ([]ai.RAGChunk, error) {
	return m.ingested, nil
}

func (m *mockRAGRetriever) Ingest(_ context.Context, chunks []ai.RAGChunk) error {
	m.ingested = append(m.ingested, chunks...)
	return nil
}

func TestLoadRAGDocuments_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docs.json")

	docFile := ragDocumentFile{
		Documents: []ragDocumentEntry{
			{ID: "doc-1", Content: "SoapBucket is a reverse proxy.", Source: "faq"},
			{ID: "doc-2", Content: "The proxy supports MCP protocol.", Source: "docs", Metadata: map[string]string{"category": "mcp"}},
		},
	}
	data, _ := json.Marshal(docFile)
	os.WriteFile(path, data, 0644)

	retriever := &mockRAGRetriever{}
	err := loadRAGDocuments(retriever, path)
	if err != nil {
		t.Fatal(err)
	}

	if len(retriever.ingested) != 2 {
		t.Fatalf("expected 2 documents ingested, got %d", len(retriever.ingested))
	}
	if retriever.ingested[0].ID != "doc-1" {
		t.Fatalf("expected doc-1, got %s", retriever.ingested[0].ID)
	}
	if retriever.ingested[0].Content != "SoapBucket is a reverse proxy." {
		t.Fatalf("unexpected content: %s", retriever.ingested[0].Content)
	}
	if retriever.ingested[1].Source != "docs" {
		t.Fatalf("expected source 'docs', got %s", retriever.ingested[1].Source)
	}
}

func TestLoadRAGDocuments_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docs.json")

	docFile := ragDocumentFile{Documents: []ragDocumentEntry{}}
	data, _ := json.Marshal(docFile)
	os.WriteFile(path, data, 0644)

	retriever := &mockRAGRetriever{}
	err := loadRAGDocuments(retriever, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(retriever.ingested) != 0 {
		t.Fatalf("expected 0 documents ingested, got %d", len(retriever.ingested))
	}
}

func TestLoadRAGDocuments_MissingFile(t *testing.T) {
	retriever := &mockRAGRetriever{}
	err := loadRAGDocuments(retriever, "/nonexistent/docs.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadRAGDocuments_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docs.json")
	os.WriteFile(path, []byte("not json"), 0644)

	retriever := &mockRAGRetriever{}
	err := loadRAGDocuments(retriever, path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
