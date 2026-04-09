package rag

import (
	"context"
	"errors"
	"testing"

	json "github.com/goccy/go-json"
)

func TestVertexProvider_NewRequiresConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]string
		wantErr string
	}{
		{
			name:    "missing project_id",
			config:  map[string]string{"corpus_id": "123"},
			wantErr: "project_id is required",
		},
		{
			name:    "missing corpus_id",
			config:  map[string]string{"project_id": "my-project"},
			wantErr: "corpus_id is required",
		},
		{
			name:    "empty config",
			config:  map[string]string{},
			wantErr: "project_id is required",
		},
		{
			name:   "valid minimal config",
			config: map[string]string{"project_id": "my-project", "corpus_id": "123"},
		},
		{
			name: "valid full config",
			config: map[string]string{
				"project_id":       "my-project",
				"corpus_id":        "123",
				"location":         "europe-west1",
				"model":            "gemini-2.0-pro",
				"credentials_json": "eyJhbGciOiJSUzI1NiJ9...",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewVertexProvider(tt.config)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p == nil {
				t.Fatal("expected non-nil provider")
			}
		})
	}
}

func TestVertexProvider_Defaults(t *testing.T) {
	p, err := NewVertexProvider(map[string]string{
		"project_id": "my-project",
		"corpus_id":  "123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	vp := p.(*VertexProvider)
	if vp.location != vertexDefaultLocation {
		t.Errorf("expected default location %q, got %q", vertexDefaultLocation, vp.location)
	}
	if vp.model != vertexDefaultModel {
		t.Errorf("expected default model %q, got %q", vertexDefaultModel, vp.model)
	}
	wantURL := "https://us-central1-aiplatform.googleapis.com/v1"
	if vp.baseURL != wantURL {
		t.Errorf("expected baseURL %q, got %q", wantURL, vp.baseURL)
	}
}

func TestVertexProvider_CustomLocation(t *testing.T) {
	p, err := NewVertexProvider(map[string]string{
		"project_id": "my-project",
		"corpus_id":  "123",
		"location":   "europe-west1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	vp := p.(*VertexProvider)
	wantURL := "https://europe-west1-aiplatform.googleapis.com/v1"
	if vp.baseURL != wantURL {
		t.Errorf("expected baseURL %q, got %q", wantURL, vp.baseURL)
	}
}

func TestVertexProvider_Name(t *testing.T) {
	p, err := NewVertexProvider(map[string]string{
		"project_id": "my-project",
		"corpus_id":  "123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := p.Name(); got != "vertex" {
		t.Errorf("Name() = %q, want %q", got, "vertex")
	}
}

func TestVertexProvider_StubMethodsReturnErrNotConfigured(t *testing.T) {
	p, err := NewVertexProvider(map[string]string{
		"project_id": "my-project",
		"corpus_id":  "123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ctx := context.Background()

	t.Run("Ingest", func(t *testing.T) {
		err := p.Ingest(ctx, []Document{{ID: "1", Content: []byte("hello")}})
		if !errors.Is(err, ErrNotConfigured) {
			t.Errorf("Ingest() error = %v, want ErrNotConfigured", err)
		}
	})

	t.Run("Query", func(t *testing.T) {
		_, err := p.Query(ctx, "test question")
		if !errors.Is(err, ErrNotConfigured) {
			t.Errorf("Query() error = %v, want ErrNotConfigured", err)
		}
	})

	t.Run("Retrieve", func(t *testing.T) {
		_, err := p.Retrieve(ctx, "test question", 5)
		if !errors.Is(err, ErrNotConfigured) {
			t.Errorf("Retrieve() error = %v, want ErrNotConfigured", err)
		}
	})

	t.Run("Health", func(t *testing.T) {
		err := p.Health(ctx)
		if !errors.Is(err, ErrNotConfigured) {
			t.Errorf("Health() error = %v, want ErrNotConfigured", err)
		}
	})

	t.Run("Close", func(t *testing.T) {
		err := p.Close()
		if err != nil {
			t.Errorf("Close() error = %v, want nil", err)
		}
	})
}

func TestVertexProvider_RetrieveContextsRequestMarshal(t *testing.T) {
	data := vertexRetrieveContextsRequestJSON("What is machine learning?", 10)

	var got vertexRetrieveContextsRequest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if got.Query.Text != "What is machine learning?" {
		t.Errorf("Query.Text = %q, want %q", got.Query.Text, "What is machine learning?")
	}
	if got.RagRetrievalConfig.TopK != 10 {
		t.Errorf("TopK = %d, want %d", got.RagRetrievalConfig.TopK, 10)
	}
}

func TestVertexProvider_GenerateContentRequestMarshal(t *testing.T) {
	data := vertexGenerateContentRequestJSON("Explain RAG", 0.3, 1024)

	var got vertexGenerateContentRequest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if len(got.Contents) != 1 {
		t.Fatalf("len(Contents) = %d, want 1", len(got.Contents))
	}
	if got.Contents[0].Role != "user" {
		t.Errorf("Role = %q, want %q", got.Contents[0].Role, "user")
	}
	if len(got.Contents[0].Parts) != 1 {
		t.Fatalf("len(Parts) = %d, want 1", len(got.Contents[0].Parts))
	}
	if got.Contents[0].Parts[0].Text != "Explain RAG" {
		t.Errorf("Text = %q, want %q", got.Contents[0].Parts[0].Text, "Explain RAG")
	}
	if got.GenerationConfig.Temperature != 0.3 {
		t.Errorf("Temperature = %f, want 0.3", got.GenerationConfig.Temperature)
	}
	if got.GenerationConfig.MaxTokens != 1024 {
		t.Errorf("MaxTokens = %d, want 1024", got.GenerationConfig.MaxTokens)
	}
}

func TestVertexProvider_RetrieveContextsResponseMarshal(t *testing.T) {
	resp := vertexRetrieveContextsResponse{
		Contexts: vertexContexts{
			Contexts: []vertexContext{
				{SourceURI: "gs://bucket/doc1.pdf", Text: "Machine learning is...", Score: 0.92},
				{SourceURI: "gs://bucket/doc2.pdf", Text: "Deep learning uses...", Score: 0.85},
			},
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var got vertexRetrieveContextsResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if len(got.Contexts.Contexts) != 2 {
		t.Fatalf("len(Contexts) = %d, want 2", len(got.Contexts.Contexts))
	}
	if got.Contexts.Contexts[0].Score != 0.92 {
		t.Errorf("Score = %f, want 0.92", got.Contexts.Contexts[0].Score)
	}
	if got.Contexts.Contexts[1].SourceURI != "gs://bucket/doc2.pdf" {
		t.Errorf("SourceURI = %q, want %q", got.Contexts.Contexts[1].SourceURI, "gs://bucket/doc2.pdf")
	}
}

func TestVertexProvider_GenerateContentResponseMarshal(t *testing.T) {
	resp := vertexGenerateContentResponse{
		Candidates: []vertexCandidate{
			{
				Content: vertexContent{
					Role:  "model",
					Parts: []vertexPart{{Text: "RAG combines retrieval with generation."}},
				},
			},
		},
		UsageMetadata: vertexUsageMetadata{
			PromptTokenCount:     150,
			CandidatesTokenCount: 42,
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var got vertexGenerateContentResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if len(got.Candidates) != 1 {
		t.Fatalf("len(Candidates) = %d, want 1", len(got.Candidates))
	}
	if got.Candidates[0].Content.Parts[0].Text != "RAG combines retrieval with generation." {
		t.Errorf("Text = %q, want %q", got.Candidates[0].Content.Parts[0].Text, "RAG combines retrieval with generation.")
	}
	if got.UsageMetadata.PromptTokenCount != 150 {
		t.Errorf("PromptTokenCount = %d, want 150", got.UsageMetadata.PromptTokenCount)
	}
	if got.UsageMetadata.CandidatesTokenCount != 42 {
		t.Errorf("CandidatesTokenCount = %d, want 42", got.UsageMetadata.CandidatesTokenCount)
	}
}
