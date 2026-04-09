package guardrails

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMaxTokens_WithinLimit(t *testing.T) {
	g, err := NewMaxTokensGuard(json.RawMessage(`{"max_tokens": 100}`))
	require.NoError(t, err)

	content := testContent("Hello world")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass)
}

func TestMaxTokens_ExceedsLimit(t *testing.T) {
	g, err := NewMaxTokensGuard(json.RawMessage(`{"max_tokens": 10}`))
	require.NoError(t, err)

	// ~15 tokens: 60 chars / 4 = 15
	content := testContent("This is a somewhat longer text that exceeds the limit")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Contains(t, result.Reason, "exceeds token limit")
	assert.Equal(t, 10, result.Details["max_tokens"])
}

func TestMaxTokens_DefaultLimit(t *testing.T) {
	g, err := NewMaxTokensGuard(nil)
	require.NoError(t, err)

	// Default is 16000 tokens
	content := testContent("Short text")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass)
}

func TestMaxTokens_LargeText(t *testing.T) {
	g, err := NewMaxTokensGuard(json.RawMessage(`{"max_tokens": 100}`))
	require.NoError(t, err)

	// Create large text (~2000 chars = ~500 tokens)
	largeText := strings.Repeat("word ", 400)
	content := testContent(largeText)
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)
}

func TestMaxTokens_EmptyContent(t *testing.T) {
	g, err := NewMaxTokensGuard(json.RawMessage(`{"max_tokens": 1}`))
	require.NoError(t, err)

	content := &Content{}
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass)
}

func TestMaxTokens_Name(t *testing.T) {
	g, err := NewMaxTokensGuard(nil)
	require.NoError(t, err)
	assert.Equal(t, "max_tokens", g.Name())
	assert.Equal(t, PhaseInput, g.Phase())
}

func TestLengthLimit_MaxWordsExceeded(t *testing.T) {
	g, err := NewLengthLimitGuard(json.RawMessage(`{"max_words": 3}`))
	require.NoError(t, err)

	result, err := g.Check(context.Background(), testContent("one two three four"))
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Contains(t, result.Reason, "max words")
}

func TestLengthLimit_MinCharsNotMet(t *testing.T) {
	g, err := NewLengthLimitGuard(json.RawMessage(`{"min_chars": 10}`))
	require.NoError(t, err)

	result, err := g.Check(context.Background(), testContent("short"))
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Contains(t, result.Reason, "few characters")
}

func TestLengthLimit_WithinBounds(t *testing.T) {
	g, err := NewLengthLimitGuard(json.RawMessage(`{"min_words": 2, "max_words": 5, "min_chars": 5, "max_chars": 40}`))
	require.NoError(t, err)

	result, err := g.Check(context.Background(), testContent("this is valid input"))
	require.NoError(t, err)
	assert.True(t, result.Pass)
}

func TestLengthLimit_Name(t *testing.T) {
	g, err := NewLengthLimitGuard(nil)
	require.NoError(t, err)
	assert.Equal(t, "length_limit", g.Name())
	assert.Equal(t, PhaseInput, g.Phase())
}
