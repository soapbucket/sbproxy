package providers

import (
	"net/http"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func TestVLLMProvider(t *testing.T) {
	cfg := &ai.ProviderConfig{Name: "vllm", Type: "vllm"}
	p, err := ai.NewProvider(cfg, http.DefaultClient)
	if err != nil {
		t.Fatalf("failed to create vllm provider: %v", err)
	}
	if p.Name() != "vllm" {
		t.Errorf("expected name 'vllm', got %q", p.Name())
	}
	if !p.SupportsStreaming() {
		t.Error("expected streaming support")
	}
	if !p.SupportsEmbeddings() {
		t.Error("expected embeddings support")
	}
}
