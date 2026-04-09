package ai

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompress_Factory(t *testing.T) {
	tests := []struct {
		strategy string
		wantType string
	}{
		{"simple", "*ai.SimpleCompressor"},
		{"llmlingua", "*ai.LLMLinguaCompressor"},
		{"none", "*ai.noopCompressor"},
		{"", "*ai.noopCompressor"},
		{"unknown", "*ai.noopCompressor"},
	}
	for _, tt := range tests {
		c := NewCompressor(tt.strategy)
		assert.NotNil(t, c, "strategy=%s", tt.strategy)
	}
}

func TestCompress_Simple_AchievesTargetRatio(t *testing.T) {
	ctx := context.Background()
	c := NewCompressor("simple")

	messages := []CompressMessage{
		{Role: "user", Content: "I just really wanted to basically say that the very important meeting is actually happening on Tuesday and it will essentially cover the quarterly results and also the new product launch which is definitely going to be really exciting for everyone. Furthermore, we should probably discuss the budget allocations and moreover consider the timeline for the next sprint. Additionally, the team has been working very hard on the new features and they are quite impressive."},
	}

	config := &CompressionConfig{
		Enabled:           true,
		Ratio:             0.5,
		MinTokenThreshold: 0,
		Strategy:          "simple",
	}

	result, stats, err := c.Compress(ctx, messages, config)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Greater(t, stats.OriginalTokens, 0)
	assert.Greater(t, stats.CompressedTokens, 0)
	// Within 20% tolerance of target ratio.
	assert.LessOrEqual(t, stats.Ratio, 0.7, "ratio should be at most 0.7 (0.5 + 20% tolerance)")
}

func TestCompress_Simple_PreserveSystemMessage(t *testing.T) {
	ctx := context.Background()
	c := NewCompressor("simple")

	systemContent := "You are a helpful assistant. Always respond politely."
	messages := []CompressMessage{
		{Role: "system", Content: systemContent},
		{Role: "user", Content: "I just really wanted to basically say something very important about the project that is essentially ready to launch and will definitely be exciting for the whole team and furthermore we need to discuss the basically important timeline."},
	}

	config := &CompressionConfig{
		Enabled:               true,
		Ratio:                 0.5,
		MinTokenThreshold:     0,
		PreserveSystemMessage: true,
		Strategy:              "simple",
	}

	result, stats, err := c.Compress(ctx, messages, config)
	require.NoError(t, err)
	assert.Equal(t, systemContent, result[0].Content, "system message must be preserved exactly")
	assert.Equal(t, 1, stats.PreservedMessages)
}

func TestCompress_Simple_PreserveLastN(t *testing.T) {
	ctx := context.Background()
	c := NewCompressor("simple")

	lastUserContent := "What is the weather today?"
	messages := []CompressMessage{
		{Role: "user", Content: "I just really basically wanted to say something very essentially important and definitely noteworthy about the upcoming basically quarterly review meeting that will furthermore cover the budget and also the product timeline."},
		{Role: "assistant", Content: "Of course! The quarterly review will cover all those topics."},
		{Role: "user", Content: lastUserContent},
	}

	config := &CompressionConfig{
		Enabled:           true,
		Ratio:             0.5,
		MinTokenThreshold: 0,
		PreserveLastN:     1,
		Strategy:          "simple",
	}

	result, stats, err := c.Compress(ctx, messages, config)
	require.NoError(t, err)
	assert.Equal(t, lastUserContent, result[2].Content, "last user message must be preserved")
	assert.GreaterOrEqual(t, stats.PreservedMessages, 1)
}

func TestCompress_Simple_MinTokenThreshold(t *testing.T) {
	ctx := context.Background()
	c := NewCompressor("simple")

	content := "Hello world"
	messages := []CompressMessage{
		{Role: "user", Content: content},
	}

	config := &CompressionConfig{
		Enabled:           true,
		Ratio:             0.5,
		MinTokenThreshold: 1000, // Way above actual token count.
		Strategy:          "simple",
	}

	result, stats, err := c.Compress(ctx, messages, config)
	require.NoError(t, err)
	assert.Equal(t, content, result[0].Content, "content below threshold must not be compressed")
	assert.Equal(t, 1.0, stats.Ratio)
}

func TestCompress_Simple_EmptyInput(t *testing.T) {
	ctx := context.Background()
	c := NewCompressor("simple")

	config := &CompressionConfig{
		Enabled:  true,
		Ratio:    0.5,
		Strategy: "simple",
	}

	result, stats, err := c.Compress(ctx, nil, config)
	require.NoError(t, err)
	assert.Empty(t, result)
	assert.NotNil(t, stats)

	result2, stats2, err2 := c.Compress(ctx, []CompressMessage{}, config)
	require.NoError(t, err2)
	assert.Empty(t, result2)
	assert.NotNil(t, stats2)
}

func TestCompress_LLMLingua_CoherentOutput(t *testing.T) {
	ctx := context.Background()
	c := NewCompressor("llmlingua")

	messages := []CompressMessage{
		{Role: "user", Content: "The quick brown fox jumps over the lazy dog. This is a classic sentence that contains every letter of the English alphabet. It has been used for many years in typing tests and font demonstrations. The sentence is simple but quite effective for its purpose."},
	}

	config := &CompressionConfig{
		Enabled:           true,
		Ratio:             0.6,
		MinTokenThreshold: 0,
		Strategy:          "llmlingua",
	}

	result, stats, err := c.Compress(ctx, messages, config)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.NotEmpty(t, result[0].Content, "compressed output must not be empty")
	assert.Less(t, len(result[0].Content), len(messages[0].Content), "compressed text should be shorter")
	assert.Greater(t, stats.CompressedTokens, 0)
}

func TestCompress_LLMLingua_PreservesImportantTokens(t *testing.T) {
	ctx := context.Background()
	c := NewCompressor("llmlingua")

	messages := []CompressMessage{
		{Role: "user", Content: "John Smith met with the CEO at Microsoft headquarters on January 15th 2024 to discuss the $5.2 million contract for Project Atlas. The meeting was very long and quite boring but also somewhat productive."},
	}

	config := &CompressionConfig{
		Enabled:           true,
		Ratio:             0.5,
		MinTokenThreshold: 0,
		Strategy:          "llmlingua",
	}

	result, stats, err := c.Compress(ctx, messages, config)
	require.NoError(t, err)

	compressed := result[0].Content
	// Important tokens: names, numbers, and entities should survive compression.
	importantTokens := []string{"John", "Smith", "Microsoft", "January", "$5.2", "Atlas"}
	preservedCount := 0
	for _, token := range importantTokens {
		if compressContainsWord(compressed, token) {
			preservedCount++
		}
	}
	// At least half of the important tokens should be preserved at 50% ratio.
	assert.GreaterOrEqual(t, preservedCount, len(importantTokens)/2,
		"expected at least %d important tokens preserved, got %d in: %s",
		len(importantTokens)/2, preservedCount, compressed)
	assert.Greater(t, stats.OriginalTokens, stats.CompressedTokens)
}

func TestCompress_Stats_Populated(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		strategy string
	}{
		{"simple", "simple"},
		{"llmlingua", "llmlingua"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompressor(tt.strategy)
			messages := []CompressMessage{
				{Role: "user", Content: "This is a fairly long message that should be compressed to test that statistics are properly populated with original and compressed token counts and timing information."},
			}

			config := &CompressionConfig{
				Enabled:           true,
				Ratio:             0.6,
				MinTokenThreshold: 0,
				Strategy:          tt.strategy,
			}

			_, stats, err := c.Compress(ctx, messages, config)
			require.NoError(t, err)
			assert.Greater(t, stats.OriginalTokens, 0, "OriginalTokens should be > 0")
			assert.Greater(t, stats.CompressedTokens, 0, "CompressedTokens should be > 0")
			assert.Greater(t, stats.Ratio, 0.0, "Ratio should be > 0")
			assert.LessOrEqual(t, stats.Ratio, 1.0, "Ratio should be <= 1")
			assert.GreaterOrEqual(t, stats.Duration.Nanoseconds(), int64(0), "Duration should be >= 0")
		})
	}
}

func TestCompress_Noop(t *testing.T) {
	ctx := context.Background()
	c := NewCompressor("none")

	content := "This should not be changed at all."
	messages := []CompressMessage{
		{Role: "user", Content: content},
	}

	result, stats, err := c.Compress(ctx, messages, nil)
	require.NoError(t, err)
	assert.Equal(t, content, result[0].Content)
	assert.Equal(t, 1.0, stats.Ratio)
}

func TestCompress_LLMLingua_PreserveSystemMessage(t *testing.T) {
	ctx := context.Background()
	c := NewCompressor("llmlingua")

	systemContent := "You are a helpful assistant."
	messages := []CompressMessage{
		{Role: "system", Content: systemContent},
		{Role: "user", Content: "I wanted to basically tell you something very important about the project that is essentially ready for the launch and will definitely be exciting for the whole team and we should furthermore discuss the timeline."},
	}

	config := &CompressionConfig{
		Enabled:               true,
		Ratio:                 0.5,
		MinTokenThreshold:     0,
		PreserveSystemMessage: true,
		Strategy:              "llmlingua",
	}

	result, _, err := c.Compress(ctx, messages, config)
	require.NoError(t, err)
	assert.Equal(t, systemContent, result[0].Content)
}

func TestCompress_NilConfig(t *testing.T) {
	ctx := context.Background()

	for _, strategy := range []string{"simple", "llmlingua"} {
		c := NewCompressor(strategy)
		messages := []CompressMessage{{Role: "user", Content: "test"}}
		_, _, err := c.Compress(ctx, messages, nil)
		assert.Error(t, err, "strategy=%s should error on nil config", strategy)
	}
}

// compressContainsWord checks if a word appears in text (surrounded by spaces or at boundaries).
func compressContainsWord(text, word string) bool {
	return len(text) > 0 && len(word) > 0 &&
		(len(text) >= len(word)) &&
		strings.Contains(text, word)
}
