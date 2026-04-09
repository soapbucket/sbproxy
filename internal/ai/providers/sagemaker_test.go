package providers

import (
	"net/http"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func TestSageMakerProvider(t *testing.T) {
	cfg := &ai.ProviderConfig{Name: "sagemaker", Type: "sagemaker"}
	p, err := ai.NewProvider(cfg, http.DefaultClient)
	if err != nil {
		t.Fatalf("failed to create sagemaker provider: %v", err)
	}
	if p.Name() != "sagemaker" {
		t.Errorf("expected name 'sagemaker', got %q", p.Name())
	}
	if !p.SupportsStreaming() {
		t.Error("expected streaming support")
	}
	if !p.SupportsEmbeddings() {
		t.Error("expected embeddings support")
	}
}

func TestSageMaker_ChatCompletion_CoreBuild(t *testing.T) {
	p := NewSageMaker(http.DefaultClient)
	cfg := &ai.ProviderConfig{
		Name:   "sagemaker",
		APIKey: "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	_, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model:    "test-model",
		Messages: []ai.Message{{Role: "user", Content: mustJSON("Hi")}},
	}, cfg)
	if err == nil {
		t.Fatal("expected error in core build, got nil")
	}
	if err.Error() != errSageMakerNotAvailable.Error() {
		t.Errorf("expected errSageMakerNotAvailable, got: %v", err)
	}
}

func TestSageMaker_ChatCompletionStream_CoreBuild(t *testing.T) {
	p := NewSageMaker(http.DefaultClient)
	cfg := &ai.ProviderConfig{
		Name:   "sagemaker",
		APIKey: "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	_, err := p.ChatCompletionStream(t.Context(), &ai.ChatCompletionRequest{
		Model:    "test-model",
		Messages: []ai.Message{{Role: "user", Content: mustJSON("Hi")}},
	}, cfg)
	if err == nil {
		t.Fatal("expected error in core build, got nil")
	}
}

func TestSageMaker_Embeddings_CoreBuild(t *testing.T) {
	p := NewSageMaker(http.DefaultClient)
	cfg := &ai.ProviderConfig{
		Name:   "sagemaker",
		APIKey: "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	_, err := p.Embeddings(t.Context(), &ai.EmbeddingRequest{
		Input: "hello world",
		Model: "my-embed-model",
	}, cfg)
	if err == nil {
		t.Fatal("expected error in core build, got nil")
	}
}

func TestSageMaker_ListModelsReturnsNil(t *testing.T) {
	p := &SageMaker{}
	models, err := p.ListModels(t.Context(), &ai.ProviderConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if models != nil {
		t.Errorf("expected nil models, got %v", models)
	}
}
