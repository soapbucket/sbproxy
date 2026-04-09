package providers

import (
	"net/http"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func TestOllamaProvider(t *testing.T) {
	cfg := &ai.ProviderConfig{Name: "ollama", Type: "ollama"}
	p, err := ai.NewProvider(cfg, http.DefaultClient)
	if err != nil {
		t.Fatalf("failed to create ollama provider: %v", err)
	}
	if p.Name() != "ollama" {
		t.Errorf("expected name 'ollama', got %q", p.Name())
	}
	if !p.SupportsStreaming() {
		t.Error("expected streaming support")
	}
	if !p.SupportsEmbeddings() {
		t.Error("expected embeddings support")
	}
}
