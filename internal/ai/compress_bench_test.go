package ai

import (
	"context"
	"math/rand"
	"strings"
	"testing"
)

// generateText creates a realistic multi-sentence text of approximately the given token count.
func generateText(approxTokens int) string {
	sentences := []string{
		"The quarterly financial report indicates a significant increase in revenue across all product lines.",
		"Our engineering team has been working diligently on the new microservices architecture.",
		"The customer satisfaction survey results show a very positive trend compared to last year.",
		"We need to basically discuss the timeline for the upcoming product launch in Q3.",
		"The data analytics platform has essentially processed over 2 million requests this month.",
		"John Smith from the London office will be presenting the European market analysis.",
		"The machine learning model achieved 95.7% accuracy on the validation dataset.",
		"Project Atlas requires an additional $3.2 million in funding for the next phase.",
		"The security audit identified several areas where we could improve our infrastructure.",
		"Microsoft and Google have both announced competing products in this space.",
		"The board of directors has approved the new strategic initiative for 2024.",
		"Performance benchmarks show a 40% improvement over the previous implementation.",
		"The API gateway handles approximately 50,000 requests per second at peak load.",
		"We should probably consider migrating the legacy systems to cloud-native solutions.",
		"The user experience research team conducted interviews with 150 participants.",
		"Database replication latency has been reduced to under 5 milliseconds.",
		"The compliance team has reviewed all documentation for GDPR requirements.",
		"Our competitive analysis shows we are leading in three key market segments.",
		"The DevOps pipeline now supports automated canary deployments across regions.",
		"Customer retention rates have improved by 12% following the UI redesign.",
	}

	rng := rand.New(rand.NewSource(42))
	var buf strings.Builder
	currentTokens := 0
	for currentTokens < approxTokens {
		idx := rng.Intn(len(sentences))
		buf.WriteString(sentences[idx])
		buf.WriteByte(' ')
		currentTokens += EstimateTokens(sentences[idx])
	}
	return buf.String()
}

func benchmarkCompress(b *testing.B, strategy string, approxTokens int) {
	ctx := context.Background()
	c := NewCompressor(strategy)
	text := generateText(approxTokens)

	messages := []CompressMessage{
		{Role: "system", Content: "You are a helpful assistant."},
		{Role: "user", Content: text},
	}

	config := &CompressionConfig{
		Enabled:               true,
		Ratio:                 0.5,
		MinTokenThreshold:     0,
		PreserveSystemMessage: true,
		Strategy:              strategy,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _ = c.Compress(ctx, messages, config)
	}
}

func BenchmarkSimpleCompress_4K(b *testing.B) {
	benchmarkCompress(b, "simple", 4000)
}

func BenchmarkSimpleCompress_16K(b *testing.B) {
	benchmarkCompress(b, "simple", 16000)
}

func BenchmarkLLMLinguaCompress_4K(b *testing.B) {
	benchmarkCompress(b, "llmlingua", 4000)
}

func BenchmarkLLMLinguaCompress_16K(b *testing.B) {
	benchmarkCompress(b, "llmlingua", 16000)
}
