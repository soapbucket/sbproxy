package ai

import (
	"testing"

	json "github.com/goccy/go-json"
)

func TestRerankRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		req     RerankRequest
		wantErr bool
	}{
		{
			name: "valid minimal",
			req: RerankRequest{
				Model:     "rerank-english-v3.0",
				Query:     "What is the capital of France?",
				Documents: json.RawMessage(`["Paris is the capital of France", "Berlin is the capital of Germany"]`),
			},
			wantErr: false,
		},
		{
			name: "missing model",
			req: RerankRequest{
				Query:     "test",
				Documents: json.RawMessage(`["doc1"]`),
			},
			wantErr: true,
		},
		{
			name: "missing query",
			req: RerankRequest{
				Model:     "rerank-english-v3.0",
				Documents: json.RawMessage(`["doc1"]`),
			},
			wantErr: true,
		},
		{
			name: "missing documents",
			req: RerankRequest{
				Model: "rerank-english-v3.0",
				Query: "test",
			},
			wantErr: true,
		},
		{
			name: "documents not array",
			req: RerankRequest{
				Model:     "rerank-english-v3.0",
				Query:     "test",
				Documents: json.RawMessage(`"not an array"`),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRerankRequest_DocumentStrings(t *testing.T) {
	req := RerankRequest{
		Documents: json.RawMessage(`["doc one", "doc two", "doc three"]`),
	}

	docs := req.DocumentStrings()
	if len(docs) != 3 {
		t.Fatalf("expected 3 documents, got %d", len(docs))
	}
	if docs[0] != "doc one" {
		t.Errorf("docs[0] = %q, want %q", docs[0], "doc one")
	}
}

func TestTranslateRerankRequest_Cohere(t *testing.T) {
	req := &RerankRequest{
		Model:           "rerank-english-v3.0",
		Query:           "What is deep learning?",
		Documents:       json.RawMessage(`["Deep learning is a subset of ML", "Go is a programming language"]`),
		TopN:            1,
		ReturnDocuments: true,
	}

	result, err := TranslateRerankRequest("cohere", req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result["model"] != "rerank-english-v3.0" {
		t.Errorf("model = %v, want rerank-english-v3.0", result["model"])
	}
	if result["query"] != "What is deep learning?" {
		t.Errorf("query = %v", result["query"])
	}
	if result["top_n"] != 1 {
		t.Errorf("top_n = %v, want 1", result["top_n"])
	}
	if result["return_documents"] != true {
		t.Errorf("return_documents = %v, want true", result["return_documents"])
	}

	// Verify documents are present.
	docs, ok := result["documents"].(json.RawMessage)
	if !ok {
		t.Fatal("documents should be json.RawMessage")
	}
	if len(docs) == 0 {
		t.Error("documents should not be empty")
	}
}

func TestTranslateRerankRequest_Jina(t *testing.T) {
	req := &RerankRequest{
		Model:     "jina-reranker-v2-base-multilingual",
		Query:     "What is deep learning?",
		Documents: json.RawMessage(`["doc1", "doc2"]`),
		TopN:      2,
	}

	result, err := TranslateRerankRequest("jina", req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result["model"] != "jina-reranker-v2-base-multilingual" {
		t.Errorf("model = %v", result["model"])
	}
	if result["top_n"] != 2 {
		t.Errorf("top_n = %v, want 2", result["top_n"])
	}
}

func TestTranslateRerankResponse_Cohere(t *testing.T) {
	body := `{
		"id": "rerank-abc123",
		"results": [
			{"index": 0, "relevance_score": 0.98, "document": {"text": "Deep learning is a subset of ML"}},
			{"index": 1, "relevance_score": 0.12, "document": {"text": "Go is a programming language"}}
		],
		"meta": {
			"billed_units": {
				"search_units": 1
			}
		}
	}`

	resp, err := TranslateRerankResponse("cohere", []byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.ID != "rerank-abc123" {
		t.Errorf("ID = %q", resp.ID)
	}
	if len(resp.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(resp.Results))
	}
	if resp.Results[0].RelevanceScore != 0.98 {
		t.Errorf("Results[0].RelevanceScore = %f, want 0.98", resp.Results[0].RelevanceScore)
	}
	if resp.Results[0].Document == nil || resp.Results[0].Document.Text != "Deep learning is a subset of ML" {
		t.Errorf("Results[0].Document.Text mismatch")
	}
	if resp.Usage == nil || resp.Usage.TotalTokens != 1 {
		t.Errorf("Usage.TotalTokens = %v, want 1", resp.Usage)
	}
}

func TestTranslateRerankResponse_Jina(t *testing.T) {
	body := `{
		"model": "jina-reranker-v2-base-multilingual",
		"results": [
			{"index": 0, "relevance_score": 0.95, "document": {"text": "doc1"}},
			{"index": 1, "relevance_score": 0.30, "document": {"text": "doc2"}}
		],
		"usage": {
			"total_tokens": 42
		}
	}`

	resp, err := TranslateRerankResponse("jina", []byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Model != "jina-reranker-v2-base-multilingual" {
		t.Errorf("Model = %q", resp.Model)
	}
	if len(resp.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(resp.Results))
	}
	if resp.Results[0].RelevanceScore != 0.95 {
		t.Errorf("Results[0].RelevanceScore = %f, want 0.95", resp.Results[0].RelevanceScore)
	}
	if resp.Usage == nil || resp.Usage.TotalTokens != 42 {
		t.Errorf("Usage.TotalTokens = %v, want 42", resp.Usage)
	}
}

func TestTranslateRerankResponse_Empty(t *testing.T) {
	_, err := TranslateRerankResponse("cohere", nil)
	if err == nil {
		t.Error("expected error for empty body")
	}
}

func TestTranslateRerankResponse_Default(t *testing.T) {
	body := `{
		"results": [
			{"index": 0, "relevance_score": 0.9}
		],
		"model": "some-model"
	}`

	resp, err := TranslateRerankResponse("unknown", []byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(resp.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(resp.Results))
	}
	if resp.Model != "some-model" {
		t.Errorf("Model = %q", resp.Model)
	}
}
