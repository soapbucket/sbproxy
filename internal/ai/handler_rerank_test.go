package ai

import (
	"testing"

	json "github.com/goccy/go-json"
)

func TestRerankRequest_DocumentStrings_ObjectDocsReturnNil(t *testing.T) {
	req := &RerankRequest{
		Model:     "rerank-v3",
		Query:     "test",
		Documents: json.RawMessage(`[{"text": "doc1"}]`),
	}
	// Object docs should return nil from DocumentStrings.
	docs := req.DocumentStrings()
	if docs != nil {
		t.Errorf("expected nil for object documents, got %v", docs)
	}
}

func TestTranslateRerankRequest_NilRequestError(t *testing.T) {
	_, err := TranslateRerankRequest("cohere", nil)
	if err == nil {
		t.Error("expected error for nil request")
	}
}

func TestTranslateRerankRequest_InvalidRequestMissingModel(t *testing.T) {
	_, err := TranslateRerankRequest("cohere", &RerankRequest{
		Query:     "test",
		Documents: json.RawMessage(`["doc"]`),
	})
	if err == nil {
		t.Error("expected error for invalid request")
	}
}

func TestTranslateRerankResponse_EmptyBodyError(t *testing.T) {
	_, err := TranslateRerankResponse("cohere", []byte{})
	if err == nil {
		t.Error("expected error for empty body")
	}
}

func TestTranslateRerankRequest_DefaultProvider(t *testing.T) {
	req := &RerankRequest{
		Model:     "custom-reranker",
		Query:     "hello",
		Documents: json.RawMessage(`["a", "b"]`),
		TopN:      1,
	}

	result, err := TranslateRerankRequest("unknown-provider", req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["model"] != "custom-reranker" {
		t.Errorf("expected model custom-reranker, got %v", result["model"])
	}
	if result["top_n"] != 1 {
		t.Errorf("expected top_n=1, got %v", result["top_n"])
	}
}
