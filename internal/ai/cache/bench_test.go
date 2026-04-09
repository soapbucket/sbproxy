package cache

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func BenchmarkVectorSearch_100(b *testing.B) {
	benchmarkVectorSearch(b, 100)
}

func BenchmarkVectorSearch_1000(b *testing.B) {
	benchmarkVectorSearch(b, 1000)
}

func BenchmarkVectorSearch_10000(b *testing.B) {
	benchmarkVectorSearch(b, 10000)
}

func benchmarkVectorSearch(b *testing.B, n int) {
	b.Helper()
	store := NewMemoryVectorStore(n + 1)
	ctx := context.Background()
	dim := 256

	rng := rand.New(rand.NewSource(42))

	for i := 0; i < n; i++ {
		emb := make([]float32, dim)
		for j := range emb {
			emb[j] = rng.Float32()
		}
		_ = store.Store(ctx, VectorEntry{
			Key:       fmt.Sprintf("entry-%d", i),
			Embedding: emb,
			Response:  []byte("cached response"),
			CreatedAt: time.Now(),
			TTL:       time.Hour,
		})
	}

	query := make([]float32, dim)
	for i := range query {
		query[i] = rng.Float32()
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		store.Search(ctx, query, 0.9, 5)
	}
}

func BenchmarkSemanticCacheE2E(b *testing.B) {
	store := NewMemoryVectorStore(1000)
	cfg := &SemanticCacheConfig{
		Enabled:             true,
		SimilarityThreshold: 0.95,
		TTLSeconds:          3600,
	}
	sc := NewSemanticCache(cfg, store, mockEmbedFn)
	ctx := context.Background()

	// Pre-populate
	prompt := "What is the capital of France?"
	response := []byte(`{"id":"chatcmpl-123","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"The capital of France is Paris."}}]}`)
	_ = sc.Store(ctx, prompt, "gpt-4o", response)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sc.Lookup(ctx, prompt, "gpt-4o")
	}
}

func BenchmarkCosineSimilarity(b *testing.B) {
	dim := 256
	a := make([]float32, dim)
	bb := make([]float32, dim)
	rng := rand.New(rand.NewSource(42))
	for i := range a {
		a[i] = rng.Float32()
		bb[i] = rng.Float32()
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cosineSimilarity(a, bb)
	}
}

func BenchmarkCompressDecompress(b *testing.B) {
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		compressed, _ := compress(data)
		decompress(compressed)
	}
}
