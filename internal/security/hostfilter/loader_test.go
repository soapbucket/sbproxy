package hostfilter

import (
	"context"
	"errors"
	"testing"
)

type mockKeyLister struct {
	keys []string
	err  error
}

func (m *mockKeyLister) ListKeys(ctx context.Context) ([]string, error) {
	return m.keys, m.err
}

func (m *mockKeyLister) ListKeysByWorkspace(ctx context.Context, workspaceID string) ([]string, error) {
	return nil, nil
}

func TestLoadHostnames_Success(t *testing.T) {
	mock := &mockKeyLister{keys: []string{"a.com", "b.com", "c.com"}}
	keys, err := LoadHostnames(context.Background(), mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d", len(keys))
	}
}

func TestLoadHostnames_Empty(t *testing.T) {
	mock := &mockKeyLister{keys: []string{}}
	keys, err := LoadHostnames(context.Background(), mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}
}

func TestLoadHostnames_Error(t *testing.T) {
	mock := &mockKeyLister{err: errors.New("storage error")}
	_, err := LoadHostnames(context.Background(), mock)
	if err == nil {
		t.Error("expected error, got nil")
	}
}
