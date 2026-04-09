package rag

import (
	"context"
	"errors"
	"testing"

	json "github.com/goccy/go-json"
)

func TestBedrockProvider_NewRequiresKBID(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]string
		wantErr string
	}{
		{
			name:    "missing kb_id",
			config:  map[string]string{"region": "us-east-1"},
			wantErr: "kb_id is required",
		},
		{
			name:    "empty config",
			config:  map[string]string{},
			wantErr: "kb_id is required",
		},
		{
			name:   "valid minimal config",
			config: map[string]string{"kb_id": "ABCDEF1234"},
		},
		{
			name: "valid full config",
			config: map[string]string{
				"kb_id":             "ABCDEF1234",
				"region":            "eu-west-1",
				"model_arn":         "arn:aws:bedrock:eu-west-1::foundation-model/anthropic.claude-sonnet-4-20250514",
				"access_key_id":     "AKIA...",
				"secret_access_key": "secret",
				"session_token":     "token",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewBedrockProvider(tt.config)
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

func TestBedrockProvider_Defaults(t *testing.T) {
	p, err := NewBedrockProvider(map[string]string{"kb_id": "test-kb"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	bp := p.(*BedrockProvider)
	if bp.region != bedrockDefaultRegion {
		t.Errorf("expected default region %q, got %q", bedrockDefaultRegion, bp.region)
	}
	if bp.modelARN != bedrockDefaultModelARN {
		t.Errorf("expected default model ARN %q, got %q", bedrockDefaultModelARN, bp.modelARN)
	}
}

func TestBedrockProvider_Name(t *testing.T) {
	p, err := NewBedrockProvider(map[string]string{"kb_id": "test-kb"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := p.Name(); got != "bedrock" {
		t.Errorf("Name() = %q, want %q", got, "bedrock")
	}
}

func TestBedrockProvider_StubMethodsReturnErrNotConfigured(t *testing.T) {
	p, err := NewBedrockProvider(map[string]string{"kb_id": "test-kb"})
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

func TestBedrockProvider_RetrieveAndGenerateInputMarshal(t *testing.T) {
	data := bedrockRetrieveAndGenerateInputJSON("kb-123", "arn:model", "What is AI?", 10)

	var got bedrockRetrieveAndGenerateInput
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if got.KnowledgeBaseID != "kb-123" {
		t.Errorf("KnowledgeBaseID = %q, want %q", got.KnowledgeBaseID, "kb-123")
	}
	if got.ModelARN != "arn:model" {
		t.Errorf("ModelARN = %q, want %q", got.ModelARN, "arn:model")
	}
	if got.Input.Text != "What is AI?" {
		t.Errorf("Input.Text = %q, want %q", got.Input.Text, "What is AI?")
	}
	if got.RetrievalConfiguration.VectorSearchConfiguration.NumberOfResults != 10 {
		t.Errorf("NumberOfResults = %d, want %d", got.RetrievalConfiguration.VectorSearchConfiguration.NumberOfResults, 10)
	}
}

func TestBedrockProvider_RetrieveInputMarshal(t *testing.T) {
	data := bedrockRetrieveInputJSON("kb-456", "How does RAG work?", 5)

	var got bedrockRetrieveInput
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if got.KnowledgeBaseID != "kb-456" {
		t.Errorf("KnowledgeBaseID = %q, want %q", got.KnowledgeBaseID, "kb-456")
	}
	if got.RetrievalQuery.Text != "How does RAG work?" {
		t.Errorf("RetrievalQuery.Text = %q, want %q", got.RetrievalQuery.Text, "How does RAG work?")
	}
	if got.RetrievalConfiguration.VectorSearchConfiguration.NumberOfResults != 5 {
		t.Errorf("NumberOfResults = %d, want %d", got.RetrievalConfiguration.VectorSearchConfiguration.NumberOfResults, 5)
	}
}

func TestBedrockProvider_RetrieveAndGenerateOutputMarshal(t *testing.T) {
	output := bedrockRetrieveAndGenerateOutput{
		Output: bedrockTextOutput{Text: "AI is artificial intelligence."},
		Citations: []bedrockCitationGroup{
			{
				RetrievedReferences: []bedrockRetrievedReference{
					{
						Content:  bedrockReferenceContent{Text: "AI refers to..."},
						Location: bedrockReferenceLocation{S3Location: bedrockS3Location{URI: "s3://bucket/doc.pdf"}},
					},
				},
			},
		},
	}

	data, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var got bedrockRetrieveAndGenerateOutput
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if got.Output.Text != "AI is artificial intelligence." {
		t.Errorf("Output.Text = %q, want %q", got.Output.Text, "AI is artificial intelligence.")
	}
	if len(got.Citations) != 1 {
		t.Fatalf("len(Citations) = %d, want 1", len(got.Citations))
	}
	if len(got.Citations[0].RetrievedReferences) != 1 {
		t.Fatalf("len(RetrievedReferences) = %d, want 1", len(got.Citations[0].RetrievedReferences))
	}
	ref := got.Citations[0].RetrievedReferences[0]
	if ref.Content.Text != "AI refers to..." {
		t.Errorf("Content.Text = %q, want %q", ref.Content.Text, "AI refers to...")
	}
	if ref.Location.S3Location.URI != "s3://bucket/doc.pdf" {
		t.Errorf("S3Location.URI = %q, want %q", ref.Location.S3Location.URI, "s3://bucket/doc.pdf")
	}
}

func TestBedrockProvider_RetrieveOutputMarshal(t *testing.T) {
	output := bedrockRetrieveOutput{
		RetrievalResults: []bedrockRetrievalResult{
			{
				Content:  bedrockReferenceContent{Text: "chunk one"},
				Score:    0.95,
				Location: bedrockReferenceLocation{S3Location: bedrockS3Location{URI: "s3://bucket/a.pdf"}},
			},
			{
				Content:  bedrockReferenceContent{Text: "chunk two"},
				Score:    0.82,
				Location: bedrockReferenceLocation{S3Location: bedrockS3Location{URI: "s3://bucket/b.pdf"}},
			},
		},
	}

	data, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var got bedrockRetrieveOutput
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if len(got.RetrievalResults) != 2 {
		t.Fatalf("len(RetrievalResults) = %d, want 2", len(got.RetrievalResults))
	}
	if got.RetrievalResults[0].Score != 0.95 {
		t.Errorf("Score = %f, want 0.95", got.RetrievalResults[0].Score)
	}
	if got.RetrievalResults[1].Location.S3Location.URI != "s3://bucket/b.pdf" {
		t.Errorf("URI = %q, want %q", got.RetrievalResults[1].Location.S3Location.URI, "s3://bucket/b.pdf")
	}
}

// contains and searchString helpers are defined in cohere_test.go.
