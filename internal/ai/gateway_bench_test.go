package ai

import (
	"fmt"
	"testing"
)

func buildLargeRegistry(n int) *ModelRegistry {
	entries := make([]ModelRegistryEntry, 0, n)
	for i := 0; i < n; i++ {
		entries = append(entries, ModelRegistryEntry{
			ModelPattern: fmt.Sprintf("model-%d", i),
			Provider:     fmt.Sprintf("provider-%d", i%10),
			Priority:     i,
		})
	}
	return NewModelRegistry(entries)
}

func BenchmarkModelRegistryLookup(b *testing.B) {
	reg := buildLargeRegistry(1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reg.Lookup("model-500")
	}
}

func BenchmarkModelRegistryLookupGlob(b *testing.B) {
	entries := make([]ModelRegistryEntry, 0, 1000)
	for i := 0; i < 1000; i++ {
		entries = append(entries, ModelRegistryEntry{
			ModelPattern: fmt.Sprintf("provider-%d-model-*", i),
			Provider:     fmt.Sprintf("provider-%d", i%10),
			Priority:     i,
		})
	}
	reg := NewModelRegistry(entries)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reg.Lookup("provider-500-model-gpt4o")
	}
}

func BenchmarkModelRegistryLookupAll(b *testing.B) {
	// Build registry where many entries match a single model.
	entries := make([]ModelRegistryEntry, 0, 1000)
	for i := 0; i < 1000; i++ {
		entries = append(entries, ModelRegistryEntry{
			ModelPattern: "gpt-4*",
			Provider:     fmt.Sprintf("provider-%d", i),
			Priority:     i,
		})
	}
	reg := NewModelRegistry(entries)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reg.LookupAll("gpt-4o")
	}
}
