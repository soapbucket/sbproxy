package guardrails

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTopicFilter_Block(t *testing.T) {
	g, err := NewTopicFilter(json.RawMessage(`{"block_topics": ["gambling", "drugs"]}`))
	require.NoError(t, err)

	content := testContent("How do I get started with online gambling?")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Contains(t, result.Reason, "gambling")
}

func TestTopicFilter_NoMatch(t *testing.T) {
	g, err := NewTopicFilter(json.RawMessage(`{"block_topics": ["gambling"]}`))
	require.NoError(t, err)

	content := testContent("How do I cook pasta?")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass)
}

func TestTopicFilter_AllowOnly(t *testing.T) {
	g, err := NewTopicFilter(json.RawMessage(`{"allow_topics": ["cooking", "recipes"]}`))
	require.NoError(t, err)

	// Should pass — matches allowed topic
	content := testContent("Give me cooking tips for pasta")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass)

	// Should fail — doesn't match any allowed topic
	content = testContent("Tell me about astronomy")
	result, err = g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Contains(t, result.Reason, "allowed topic")
}

func TestTopicFilter_CaseInsensitive(t *testing.T) {
	g, err := NewTopicFilter(json.RawMessage(`{"block_topics": ["gambling"]}`))
	require.NoError(t, err)

	content := testContent("I want to try GAMBLING online")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)
}

func TestTopicFilter_MultipleBlocked(t *testing.T) {
	g, err := NewTopicFilter(json.RawMessage(`{"block_topics": ["violence", "weapons"]}`))
	require.NoError(t, err)

	content := testContent("Tell me about weapons and violence")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)

	matched := result.Details["matched_topics"].([]string)
	assert.Len(t, matched, 2)
}

func TestTopicFilter_Empty(t *testing.T) {
	g, err := NewTopicFilter(nil)
	require.NoError(t, err)

	content := testContent("Anything")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass)
}

func TestTopicFilter_EmptyContent(t *testing.T) {
	g, err := NewTopicFilter(json.RawMessage(`{"block_topics": ["test"]}`))
	require.NoError(t, err)

	content := &Content{}
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass)
}

func TestTopicFilter_Name(t *testing.T) {
	g, err := NewTopicFilter(nil)
	require.NoError(t, err)
	assert.Equal(t, "topic_filter", g.Name())
	assert.Equal(t, PhaseInput, g.Phase())
}
