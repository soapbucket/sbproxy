package rag

import (
	"context"
	"errors"
	"sort"
	"testing"
)

// mockProvider is a minimal Provider implementation for registry tests.
type mockProvider struct {
	name      string
	closed    bool
	closeErr  error
	healthErr error
}

func (m *mockProvider) Name() string                                                          { return m.name }
func (m *mockProvider) Ingest(_ context.Context, _ []Document) error                          { return nil }
func (m *mockProvider) Query(_ context.Context, _ string, _ ...QueryOption) (*QueryResult, error) {
	return &QueryResult{Provider: m.name}, nil
}
func (m *mockProvider) Retrieve(_ context.Context, _ string, _ int) ([]Citation, error) { return nil, nil }
func (m *mockProvider) Health(_ context.Context) error                                   { return m.healthErr }
func (m *mockProvider) Close() error {
	m.closed = true
	return m.closeErr
}

func TestRegistry(t *testing.T) {
	t.Parallel()

	t.Run("Create/success", func(t *testing.T) {
		t.Parallel()

		r := NewRegistry()
		r.RegisterFactory("mock", func(config map[string]string) (Provider, error) {
			return &mockProvider{name: "mock"}, nil
		})

		p, err := r.Create(ProviderConfig{Type: "mock", Config: map[string]string{}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.Name() != "mock" {
			t.Errorf("expected name %q, got %q", "mock", p.Name())
		}
	})

	t.Run("Create/unknown_type", func(t *testing.T) {
		t.Parallel()

		r := NewRegistry()
		_, err := r.Create(ProviderConfig{Type: "nonexistent", Config: map[string]string{}})
		if err == nil {
			t.Fatal("expected error for unknown type")
		}
		if got := err.Error(); got != `unknown provider type: "nonexistent"` {
			t.Errorf("unexpected error: %q", got)
		}
	})

	t.Run("Create/factory_error", func(t *testing.T) {
		t.Parallel()

		r := NewRegistry()
		r.RegisterFactory("failing", func(config map[string]string) (Provider, error) {
			return nil, errors.New("factory broke")
		})

		_, err := r.Create(ProviderConfig{Type: "failing", Config: map[string]string{}})
		if err == nil {
			t.Fatal("expected error from factory")
		}
		if got := err.Error(); got != `create provider "failing": factory broke` {
			t.Errorf("unexpected error: %q", got)
		}
	})

	t.Run("Get/found", func(t *testing.T) {
		t.Parallel()

		r := NewRegistry()
		r.RegisterFactory("mock", func(config map[string]string) (Provider, error) {
			return &mockProvider{name: "mock"}, nil
		})

		_, err := r.Create(ProviderConfig{Type: "mock", Config: map[string]string{}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		p, ok := r.Get("mock")
		if !ok {
			t.Fatal("expected provider to be found")
		}
		if p.Name() != "mock" {
			t.Errorf("expected name %q, got %q", "mock", p.Name())
		}
	})

	t.Run("Get/not_found", func(t *testing.T) {
		t.Parallel()

		r := NewRegistry()
		_, ok := r.Get("missing")
		if ok {
			t.Fatal("expected provider not to be found")
		}
	})

	t.Run("List/empty", func(t *testing.T) {
		t.Parallel()

		r := NewRegistry()
		names := r.List()
		if len(names) != 0 {
			t.Errorf("expected empty list, got %v", names)
		}
	})

	t.Run("List/multiple_providers", func(t *testing.T) {
		t.Parallel()

		r := NewRegistry()
		r.RegisterFactory("alpha", func(config map[string]string) (Provider, error) {
			return &mockProvider{name: "alpha"}, nil
		})
		r.RegisterFactory("beta", func(config map[string]string) (Provider, error) {
			return &mockProvider{name: "beta"}, nil
		})

		r.Create(ProviderConfig{Type: "alpha", Config: map[string]string{}})
		r.Create(ProviderConfig{Type: "beta", Config: map[string]string{}})

		names := r.List()
		sort.Strings(names)
		if len(names) != 2 {
			t.Fatalf("expected 2 names, got %d", len(names))
		}
		if names[0] != "alpha" || names[1] != "beta" {
			t.Errorf("unexpected names: %v", names)
		}
	})

	t.Run("SupportedTypes/empty", func(t *testing.T) {
		t.Parallel()

		r := NewRegistry()
		types := r.SupportedTypes()
		if len(types) != 0 {
			t.Errorf("expected empty types, got %v", types)
		}
	})

	t.Run("SupportedTypes/with_factories", func(t *testing.T) {
		t.Parallel()

		r := NewRegistry()
		r.RegisterFactory("x", func(config map[string]string) (Provider, error) { return nil, nil })
		r.RegisterFactory("y", func(config map[string]string) (Provider, error) { return nil, nil })

		types := r.SupportedTypes()
		sort.Strings(types)
		if len(types) != 2 {
			t.Fatalf("expected 2 types, got %d", len(types))
		}
		if types[0] != "x" || types[1] != "y" {
			t.Errorf("unexpected types: %v", types)
		}
	})

	t.Run("CloseAll/success", func(t *testing.T) {
		t.Parallel()

		r := NewRegistry()
		mp1 := &mockProvider{name: "one"}
		mp2 := &mockProvider{name: "two"}

		r.RegisterFactory("one", func(config map[string]string) (Provider, error) { return mp1, nil })
		r.RegisterFactory("two", func(config map[string]string) (Provider, error) { return mp2, nil })

		r.Create(ProviderConfig{Type: "one", Config: map[string]string{}})
		r.Create(ProviderConfig{Type: "two", Config: map[string]string{}})

		if err := r.CloseAll(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !mp1.closed {
			t.Error("provider 'one' was not closed")
		}
		if !mp2.closed {
			t.Error("provider 'two' was not closed")
		}

		// After CloseAll, list should be empty.
		if names := r.List(); len(names) != 0 {
			t.Errorf("expected empty list after CloseAll, got %v", names)
		}
	})

	t.Run("CloseAll/with_error", func(t *testing.T) {
		t.Parallel()

		r := NewRegistry()
		mp := &mockProvider{name: "err", closeErr: errors.New("close failed")}
		r.RegisterFactory("err", func(config map[string]string) (Provider, error) { return mp, nil })
		r.Create(ProviderConfig{Type: "err", Config: map[string]string{}})

		err := r.CloseAll()
		if err == nil {
			t.Fatal("expected error from CloseAll")
		}
		if got := err.Error(); got != `close provider "err": close failed` {
			t.Errorf("unexpected error: %q", got)
		}
	})

	t.Run("CloseAll/empty_registry", func(t *testing.T) {
		t.Parallel()

		r := NewRegistry()
		if err := r.CloseAll(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("DefaultRegistry/has_all_factories", func(t *testing.T) {
		t.Parallel()

		r := DefaultRegistry()
		types := r.SupportedTypes()
		sort.Strings(types)

		expected := []string{"bedrock", "cloudflare", "cohere", "nuclia", "pinecone", "ragie", "redis", "vectara", "vertex"}
		if len(types) != len(expected) {
			t.Fatalf("expected %d types, got %d: %v", len(expected), len(types), types)
		}
		for i, e := range expected {
			if types[i] != e {
				t.Errorf("type %d: got %q, want %q", i, types[i], e)
			}
		}
	})

	t.Run("SecretConfigKeys/known_providers", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			provider string
			keys     []string
		}{
			{"pinecone", []string{"api_key"}},
			{"vectara", []string{"api_key"}},
			{"bedrock", []string{"access_key_id", "secret_access_key", "session_token"}},
			{"vertex", []string{"credentials_json"}},
			{"ragie", []string{"api_key"}},
			{"cloudflare", []string{"api_token"}},
			{"nuclia", []string{"api_key"}},
			{"cohere", []string{"api_key"}},
			{"redis", []string{"redis_url", "embedding_api_key", "llm_api_key"}},
		}

		for _, tt := range tests {
			keys := SecretConfigKeys(tt.provider)
			if len(keys) != len(tt.keys) {
				t.Errorf("%s: expected %d secret keys, got %d", tt.provider, len(tt.keys), len(keys))
				continue
			}
			for i, k := range tt.keys {
				if keys[i] != k {
					t.Errorf("%s: key %d: got %q, want %q", tt.provider, i, keys[i], k)
				}
			}
		}
	})

	t.Run("SecretConfigKeys/unknown_provider", func(t *testing.T) {
		t.Parallel()

		keys := SecretConfigKeys("unknown")
		if keys != nil {
			t.Errorf("expected nil for unknown provider, got %v", keys)
		}
	})

	t.Run("RedactConfig/masks_secrets", func(t *testing.T) {
		t.Parallel()

		config := map[string]string{
			"api_key":        "sk-1234567890abcdef",
			"assistant_name": "my-assistant",
			"base_url":       "https://example.com",
		}

		redacted := RedactConfig("pinecone", config)
		if redacted["api_key"] == "sk-1234567890abcdef" {
			t.Error("api_key should be redacted")
		}
		if redacted["api_key"] != "sk***ef" {
			t.Errorf("unexpected redacted value: %q", redacted["api_key"])
		}
		if redacted["assistant_name"] != "my-assistant" {
			t.Error("non-secret key should not be redacted")
		}
		if redacted["base_url"] != "https://example.com" {
			t.Error("non-secret key should not be redacted")
		}
	})

	t.Run("RedactConfig/short_secret", func(t *testing.T) {
		t.Parallel()

		config := map[string]string{
			"api_key": "abc",
		}

		redacted := RedactConfig("pinecone", config)
		if redacted["api_key"] != "***" {
			t.Errorf("short secret should be fully masked, got %q", redacted["api_key"])
		}
	})

	t.Run("RedactConfig/empty_secret", func(t *testing.T) {
		t.Parallel()

		config := map[string]string{
			"api_key": "",
		}

		redacted := RedactConfig("pinecone", config)
		if redacted["api_key"] != "" {
			t.Errorf("empty secret should remain empty, got %q", redacted["api_key"])
		}
	})

	t.Run("RegisterFactory/overwrite", func(t *testing.T) {
		t.Parallel()

		r := NewRegistry()
		r.RegisterFactory("dup", func(config map[string]string) (Provider, error) {
			return &mockProvider{name: "first"}, nil
		})
		r.RegisterFactory("dup", func(config map[string]string) (Provider, error) {
			return &mockProvider{name: "second"}, nil
		})

		p, err := r.Create(ProviderConfig{Type: "dup", Config: map[string]string{}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.Name() != "second" {
			t.Errorf("expected overwritten factory, got name %q", p.Name())
		}
	})
}
