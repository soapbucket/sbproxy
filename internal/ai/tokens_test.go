package ai

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTokenCounter_CountText(t *testing.T) {
	tc := NewTokenCounter()

	// Tiktoken-backed tests (gpt-4 uses cl100k_base)
	tests := []struct {
		text    string
		model   string
		minToks int
		maxToks int
	}{
		{"", "gpt-4", 0, 0},
		{"hello", "gpt-4", 1, 3},
		{"Hello world, this is a test of token counting.", "gpt-4", 8, 15},
		{"a", "gpt-4", 1, 1},
	}

	for _, tt := range tests {
		count := tc.CountText(tt.text, tt.model)
		assert.GreaterOrEqual(t, count, tt.minToks, "text=%q model=%s", tt.text, tt.model)
		assert.LessOrEqual(t, count, tt.maxToks, "text=%q model=%s", tt.text, tt.model)
	}
}

func TestTokenCounter_CountText_Fallback(t *testing.T) {
	tc := NewTokenCounter()
	// Unknown model falls back to character estimation
	count := tc.CountText(string(make([]byte, 1000)), "unknown-model")
	assert.GreaterOrEqual(t, count, 200)
	assert.LessOrEqual(t, count, 300)
}

func TestTokenCounter_CountMessages(t *testing.T) {
	tc := NewTokenCounter()

	messages := []Message{
		{Role: "system", Content: json.RawMessage(`"You are a helpful assistant."`)},
		{Role: "user", Content: json.RawMessage(`"Hello, how are you?"`)},
	}

	count := tc.CountMessages(messages, "gpt-4")
	// Should be > 0 and reasonable
	assert.Greater(t, count, 10)
	assert.Less(t, count, 100)
}

func TestTokenCounter_CountMessages_WithToolCalls(t *testing.T) {
	tc := NewTokenCounter()

	messages := []Message{
		{Role: "user", Content: json.RawMessage(`"What's the weather?"`)},
		{
			Role:    "assistant",
			Content: json.RawMessage(`""`),
			ToolCalls: []ToolCall{{
				ID: "call_123", Type: "function",
				Function: ToolCallFunction{Name: "get_weather", Arguments: `{"location":"NYC"}`},
			}},
		},
	}

	count := tc.CountMessages(messages, "gpt-4")
	assert.Greater(t, count, 15)
}

func TestEstimateTokens(t *testing.T) {
	assert.Equal(t, 0, EstimateTokens(""))
	assert.Equal(t, 1, EstimateTokens("hi"))
	assert.Equal(t, 250, EstimateTokens(string(make([]byte, 1000))))
}

func TestEstimateMessagesTokens(t *testing.T) {
	messages := []Message{
		{Role: "user", Content: json.RawMessage(`"Hello"`)},
	}
	count := EstimateMessagesTokens(messages)
	assert.Greater(t, count, 0)
}

func TestTokenizerForModelFallback(t *testing.T) {
	// Without registry loaded, uses heuristic fallback
	assert.Equal(t, "o200k_base", TokenizerForModel("gpt-4o"))
	assert.Equal(t, "o200k_base", TokenizerForModel("gpt-4o-mini"))
	assert.Equal(t, "o200k_base", TokenizerForModel("gpt-4-turbo"))
	assert.Equal(t, "cl100k_base", TokenizerForModel("gpt-4"))
	assert.Equal(t, "cl100k_base", TokenizerForModel("gpt-3.5-turbo"))
	assert.Equal(t, "cl100k_base", TokenizerForModel("claude-3-5-sonnet"))
	assert.Equal(t, "estimate", TokenizerForModel("unknown-model"))
}

func BenchmarkTokenCountText(b *testing.B) {
	tc := NewTokenCounter()
	text := string(make([]byte, 4000)) // ~1000 tokens

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tc.CountText(text, "gpt-4")
	}
}

func BenchmarkTokenCountMessages(b *testing.B) {
	tc := NewTokenCounter()
	messages := []Message{
		{Role: "system", Content: json.RawMessage(`"You are a helpful assistant."`)},
		{Role: "user", Content: json.RawMessage(`"Can you help me write a function that calculates fibonacci numbers efficiently?"`)},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tc.CountMessages(messages, "gpt-4")
	}
}
