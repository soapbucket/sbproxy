package ai

import (
	"sync"
	"testing"
)

func TestModelRegistry_ExactMatch(t *testing.T) {
	reg := NewModelRegistry([]ModelRegistryEntry{
		{ModelPattern: "gpt-4o", Provider: "openai", Priority: 1},
		{ModelPattern: "claude-3-opus", Provider: "anthropic", Priority: 2},
	})

	tests := []struct {
		model        string
		wantProvider string
		wantFound    bool
	}{
		{"gpt-4o", "openai", true},
		{"claude-3-opus", "anthropic", true},
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			provider, _, found := reg.Lookup(tt.model)
			if found != tt.wantFound {
				t.Errorf("Lookup(%q) found=%v, want %v", tt.model, found, tt.wantFound)
			}
			if provider != tt.wantProvider {
				t.Errorf("Lookup(%q) provider=%q, want %q", tt.model, provider, tt.wantProvider)
			}
		})
	}
}

func TestModelRegistry_GlobPattern(t *testing.T) {
	reg := NewModelRegistry([]ModelRegistryEntry{
		{ModelPattern: "gpt-4*", Provider: "openai", Priority: 1},
		{ModelPattern: "claude-*", Provider: "anthropic", Priority: 2},
	})

	tests := []struct {
		model        string
		wantProvider string
		wantFound    bool
	}{
		{"gpt-4o", "openai", true},
		{"gpt-4-turbo", "openai", true},
		{"gpt-4", "openai", true},
		{"claude-3-opus", "anthropic", true},
		{"claude-3.5-sonnet", "anthropic", true},
		{"llama-3", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			provider, _, found := reg.Lookup(tt.model)
			if found != tt.wantFound {
				t.Errorf("Lookup(%q) found=%v, want %v", tt.model, found, tt.wantFound)
			}
			if provider != tt.wantProvider {
				t.Errorf("Lookup(%q) provider=%q, want %q", tt.model, provider, tt.wantProvider)
			}
		})
	}
}

func TestModelRegistry_Priority(t *testing.T) {
	// Both patterns match "gpt-4o", but priority 1 wins.
	reg := NewModelRegistry([]ModelRegistryEntry{
		{ModelPattern: "gpt-4o", Provider: "azure", Priority: 5},
		{ModelPattern: "gpt-4o", Provider: "openai", Priority: 1},
		{ModelPattern: "gpt-4o", Provider: "fallback", Priority: 10},
	})

	provider, _, found := reg.Lookup("gpt-4o")
	if !found {
		t.Fatal("expected match for gpt-4o")
	}
	if provider != "openai" {
		t.Errorf("expected openai (priority 1), got %q", provider)
	}
}

func TestModelRegistry_NotFound(t *testing.T) {
	reg := NewModelRegistry([]ModelRegistryEntry{
		{ModelPattern: "gpt-4o", Provider: "openai", Priority: 1},
	})

	_, _, found := reg.Lookup("nonexistent-model")
	if found {
		t.Error("expected not found for nonexistent model")
	}
}

func TestModelRegistry_LookupAll(t *testing.T) {
	reg := NewModelRegistry([]ModelRegistryEntry{
		{ModelPattern: "gpt-4o", Provider: "openai", Priority: 1},
		{ModelPattern: "gpt-4*", Provider: "azure", Priority: 5},
		{ModelPattern: "gpt-4o", Provider: "fallback", Priority: 10},
		{ModelPattern: "claude-*", Provider: "anthropic", Priority: 2},
	})

	results := reg.LookupAll("gpt-4o")
	if len(results) != 3 {
		t.Fatalf("expected 3 matches, got %d", len(results))
	}
	// Verify sorted by priority.
	if results[0].Provider != "openai" || results[0].Priority != 1 {
		t.Errorf("first result should be openai (priority 1), got %q (priority %d)", results[0].Provider, results[0].Priority)
	}
	if results[1].Provider != "azure" || results[1].Priority != 5 {
		t.Errorf("second result should be azure (priority 5), got %q (priority %d)", results[1].Provider, results[1].Priority)
	}
	if results[2].Provider != "fallback" || results[2].Priority != 10 {
		t.Errorf("third result should be fallback (priority 10), got %q (priority %d)", results[2].Provider, results[2].Priority)
	}
}

func TestModelRegistry_Models(t *testing.T) {
	reg := NewModelRegistry([]ModelRegistryEntry{
		{ModelPattern: "gpt-4o", Provider: "openai", Priority: 1},
		{ModelPattern: "claude-*", Provider: "anthropic", Priority: 2},
		{ModelPattern: "gpt-4*", Provider: "azure", Priority: 5},
	})

	models := reg.Models()
	if len(models) != 3 {
		t.Fatalf("expected 3 patterns, got %d", len(models))
	}
	// They should be sorted by priority.
	if models[0] != "gpt-4o" {
		t.Errorf("first pattern should be gpt-4o, got %q", models[0])
	}
	if models[1] != "claude-*" {
		t.Errorf("second pattern should be claude-*, got %q", models[1])
	}
	if models[2] != "gpt-4*" {
		t.Errorf("third pattern should be gpt-4*, got %q", models[2])
	}
}

func TestModelRegistry_AddRemove(t *testing.T) {
	reg := NewModelRegistry([]ModelRegistryEntry{
		{ModelPattern: "gpt-4o", Provider: "openai", Priority: 1},
	})

	// Add a new entry.
	reg.AddEntry(ModelRegistryEntry{ModelPattern: "claude-*", Provider: "anthropic", Priority: 2})
	provider, _, found := reg.Lookup("claude-3-opus")
	if !found || provider != "anthropic" {
		t.Errorf("expected anthropic after add, got %q found=%v", provider, found)
	}

	// Verify priority ordering is maintained after add.
	models := reg.Models()
	if len(models) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(models))
	}
	if models[0] != "gpt-4o" {
		t.Errorf("first should be gpt-4o (priority 1), got %q", models[0])
	}

	// Add entry with lower priority (should go first).
	reg.AddEntry(ModelRegistryEntry{ModelPattern: "llama-*", Provider: "meta", Priority: 0})
	models = reg.Models()
	if models[0] != "llama-*" {
		t.Errorf("first should be llama-* (priority 0), got %q", models[0])
	}

	// Remove.
	reg.RemoveEntry("gpt-4o")
	_, _, found = reg.Lookup("gpt-4o")
	if found {
		t.Error("expected gpt-4o to be removed")
	}
}

func TestModelRegistry_ConcurrentAccess(t *testing.T) {
	reg := NewModelRegistry([]ModelRegistryEntry{
		{ModelPattern: "gpt-4o", Provider: "openai", Priority: 1},
		{ModelPattern: "claude-*", Provider: "anthropic", Priority: 2},
	})

	var wg sync.WaitGroup
	const goroutines = 100

	// Concurrent reads.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reg.Lookup("gpt-4o")
			reg.LookupAll("gpt-4o")
			reg.Models()
		}()
	}

	// Concurrent writes.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if n%2 == 0 {
				reg.AddEntry(ModelRegistryEntry{ModelPattern: "test-*", Provider: "test", Priority: n})
			} else {
				reg.RemoveEntry("test-*")
			}
		}(i)
	}

	wg.Wait()
}

func TestModelRegistry_ModelOverride(t *testing.T) {
	reg := NewModelRegistry([]ModelRegistryEntry{
		{ModelPattern: "our-gpt4", Provider: "openai", Priority: 1, ModelOverride: "gpt-4o"},
		{ModelPattern: "fast-claude", Provider: "anthropic", Priority: 2, ModelOverride: "claude-3-haiku-20240307"},
	})

	tests := []struct {
		model        string
		wantProvider string
		wantOverride string
	}{
		{"our-gpt4", "openai", "gpt-4o"},
		{"fast-claude", "anthropic", "claude-3-haiku-20240307"},
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			provider, override, found := reg.Lookup(tt.model)
			if !found {
				t.Fatalf("expected to find %q", tt.model)
			}
			if provider != tt.wantProvider {
				t.Errorf("provider=%q, want %q", provider, tt.wantProvider)
			}
			if override != tt.wantOverride {
				t.Errorf("override=%q, want %q", override, tt.wantOverride)
			}
		})
	}
}

func TestModelRegistry_EmptyRegistry(t *testing.T) {
	reg := NewModelRegistry(nil)

	_, _, found := reg.Lookup("anything")
	if found {
		t.Error("expected not found on empty registry")
	}

	results := reg.LookupAll("anything")
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}

	models := reg.Models()
	if len(models) != 0 {
		t.Errorf("expected 0 models, got %d", len(models))
	}
}

func TestModelRegistry_ExactMatchBeforeGlob(t *testing.T) {
	// Exact match at priority 5 should still beat glob at priority 1
	// because exact matches are checked first.
	reg := NewModelRegistry([]ModelRegistryEntry{
		{ModelPattern: "gpt-4*", Provider: "azure-glob", Priority: 1},
		{ModelPattern: "gpt-4o", Provider: "openai-exact", Priority: 5},
	})

	provider, _, found := reg.Lookup("gpt-4o")
	if !found {
		t.Fatal("expected match")
	}
	// Exact match has higher priority in the search (checked first),
	// but among exact matches, lower priority number still wins.
	// Here only one exact match exists: openai-exact at priority 5.
	if provider != "openai-exact" {
		t.Errorf("expected openai-exact (exact match), got %q", provider)
	}

	// A model that only matches the glob should return azure-glob.
	provider, _, found = reg.Lookup("gpt-4-turbo")
	if !found {
		t.Fatal("expected glob match for gpt-4-turbo")
	}
	if provider != "azure-glob" {
		t.Errorf("expected azure-glob for gpt-4-turbo, got %q", provider)
	}
}
