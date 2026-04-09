package cache

import (
	"context"
	"fmt"
	"testing"
)

func TestNewLocalEmbedFunc_NilClient(t *testing.T) {
	fn := NewLocalEmbedFunc(nil)
	if fn != nil {
		t.Fatal("expected nil EmbedFunc for nil client")
	}
}

func TestNewProviderEmbedFunc_NilEmbedder(t *testing.T) {
	fn := NewProviderEmbedFunc(nil, "some-model")
	if fn != nil {
		t.Fatal("expected nil EmbedFunc for nil embedder")
	}
}

// mockEmbedder records the model parameter passed to Embed.
type mockEmbedder struct {
	calledModel string
}

func (m *mockEmbedder) Embed(_ context.Context, text, model string) ([]float32, error) {
	m.calledModel = model
	return []float32{0.1, 0.2, 0.3}, nil
}

func TestNewProviderEmbedFunc_DefaultModel(t *testing.T) {
	mock := &mockEmbedder{}
	fn := NewProviderEmbedFunc(mock, "")
	if fn == nil {
		t.Fatal("expected non-nil EmbedFunc")
	}

	_, err := fn(context.Background(), "hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.calledModel != "text-embedding-3-small" {
		t.Fatalf("expected default model %q, got %q", "text-embedding-3-small", mock.calledModel)
	}
}

func TestNewProviderEmbedFunc_CustomModel(t *testing.T) {
	mock := &mockEmbedder{}
	fn := NewProviderEmbedFunc(mock, "my-custom-model")
	if fn == nil {
		t.Fatal("expected non-nil EmbedFunc")
	}

	_, err := fn(context.Background(), "hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.calledModel != "my-custom-model" {
		t.Fatalf("expected model %q, got %q", "my-custom-model", mock.calledModel)
	}
}

// errorEmbedder always returns an error.
type errorEmbedder struct{}

func (e *errorEmbedder) Embed(_ context.Context, text, model string) ([]float32, error) {
	return nil, fmt.Errorf("provider unavailable")
}

func TestNewProviderEmbedFunc_Error(t *testing.T) {
	fn := NewProviderEmbedFunc(&errorEmbedder{}, "model")
	if fn == nil {
		t.Fatal("expected non-nil EmbedFunc")
	}

	_, err := fn(context.Background(), "hello")
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "cache embedding error: provider unavailable" {
		t.Fatalf("unexpected error message: %v", err)
	}
}
