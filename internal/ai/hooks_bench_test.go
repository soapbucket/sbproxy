package ai

import (
	"context"
	"testing"
	"time"
)

func BenchmarkHookChainProcessChunk(b *testing.B) {
	chain := NewHookChain(
		TokenCounterHook{},
		BudgetTrackerHook{},
		ContentFilterHook{Blocklist: []string{"forbidden", "blocked", "banned"}},
		LoggerHook{},
	)
	meta := &StreamMeta{
		RequestID: "bench-1",
		Model:     "gpt-4",
		Provider:  "openai",
		StartTime: time.Now(),
	}
	chunk := &SSEEvent{
		Data: `{"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4","choices":[{"index":0,"delta":{"content":"hello"},"finish_reason":null}]}`,
	}
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = chain.ProcessChunk(ctx, chunk, meta)
	}
}

func BenchmarkTokenCounterHook(b *testing.B) {
	hook := TokenCounterHook{}
	meta := &StreamMeta{StartTime: time.Now()}
	chunk := &SSEEvent{
		Data: `{"id":"1","object":"chat.completion.chunk","model":"gpt-4","choices":[{"index":0,"delta":{"content":"hi"},"finish_reason":null}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`,
	}
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = hook.OnChunk(ctx, chunk, meta)
	}
}

func BenchmarkContentFilterHook(b *testing.B) {
	hook := ContentFilterHook{
		Blocklist: []string{"forbidden", "blocked", "banned", "restricted", "prohibited"},
	}
	meta := &StreamMeta{StartTime: time.Now()}
	chunk := &SSEEvent{
		Data: `{"id":"1","object":"chat.completion.chunk","model":"gpt-4","choices":[{"index":0,"delta":{"content":"This is perfectly normal content that should pass through the filter without any issues."},"finish_reason":null}]}`,
	}
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = hook.OnChunk(ctx, chunk, meta)
	}
}
