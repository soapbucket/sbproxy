package guardrails

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func BenchmarkPIIDetection(b *testing.B) {
	g, _ := NewPIIDetection(nil)
	// ~1000 words
	text := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 111)
	text += " My SSN is 123-45-6789 and email is test@example.com."
	content := testContent(text)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		g.Check(ctx, content)
	}
}

func BenchmarkInjectionDetection(b *testing.B) {
	g, _ := NewInjectionDetector(nil)
	content := testContent("You are a helpful assistant. Please help me write a function that calculates fibonacci numbers efficiently. I need the code in Python with proper error handling.")
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		g.Check(ctx, content)
	}
}

func BenchmarkGuardrailPipeline(b *testing.B) {
	cfg := &GuardrailsConfig{
		Input: []GuardrailEntry{
			{Type: "max_tokens", Action: "block", Config: json.RawMessage(`{"max_tokens": 100000}`)},
			{Type: "pii_detection", Action: "block"},
			{Type: "prompt_injection", Action: "block"},
			{Type: "regex_guard", Action: "block", Config: json.RawMessage(`{"deny": ["forbidden"]}`)},
			{Type: "topic_filter", Action: "block", Config: json.RawMessage(`{"block_topics": ["gambling"]}`)},
		},
	}

	engine, _ := NewEngine(cfg)
	// ~1000 words
	text := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 111)
	content := testContent(text)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		engine.RunInput(ctx, content)
	}
}

func BenchmarkRegexGuard(b *testing.B) {
	g, _ := NewRegexGuard(json.RawMessage(`{"deny": ["password\\s*=", "secret_key", "api_token", "private_key"]}`))
	content := testContent("This is a normal request with some text that should pass through without any issues whatsoever.")
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		g.Check(ctx, content)
	}
}

func BenchmarkTopicFilter(b *testing.B) {
	g, _ := NewTopicFilter(json.RawMessage(`{"block_topics": ["gambling", "drugs", "weapons", "violence", "pornography"]}`))
	content := testContent("How do I create a REST API with Go? I need endpoints for user management.")
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		g.Check(ctx, content)
	}
}
