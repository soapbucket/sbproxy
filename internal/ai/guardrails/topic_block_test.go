package guardrails

import (
	"context"
	"testing"

	json "github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTopicBlockGuard_BlocksMatchingTopic(t *testing.T) {
	cfg := TopicBlockConfig{
		Topics: []string{"weapons", "drugs"},
	}
	data, _ := json.Marshal(cfg)

	guard, err := NewTopicBlockGuard(data)
	require.NoError(t, err)

	result, err := guard.Check(context.Background(), &Content{Text: "Tell me about weapons manufacturing"})
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Equal(t, ActionBlock, result.Action)
	assert.Equal(t, "weapons", result.Details["matched_topic"])
}

func TestTopicBlockGuard_AllowsSafeContent(t *testing.T) {
	cfg := TopicBlockConfig{
		Topics: []string{"weapons", "drugs"},
	}
	data, _ := json.Marshal(cfg)

	guard, err := NewTopicBlockGuard(data)
	require.NoError(t, err)

	result, err := guard.Check(context.Background(), &Content{Text: "Tell me about gardening"})
	require.NoError(t, err)
	assert.True(t, result.Pass)
}

func TestTopicBlockGuard_CaseInsensitive(t *testing.T) {
	cfg := TopicBlockConfig{
		Topics: []string{"WEAPONS"},
	}
	data, _ := json.Marshal(cfg)

	guard, err := NewTopicBlockGuard(data)
	require.NoError(t, err)

	result, err := guard.Check(context.Background(), &Content{Text: "discuss weapons policy"})
	require.NoError(t, err)
	assert.False(t, result.Pass)
}

func TestTopicBlockGuard_FlagAction(t *testing.T) {
	cfg := TopicBlockConfig{
		Topics: []string{"politics"},
		Action: "flag",
	}
	data, _ := json.Marshal(cfg)

	guard, err := NewTopicBlockGuard(data)
	require.NoError(t, err)

	result, err := guard.Check(context.Background(), &Content{Text: "discuss politics"})
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Equal(t, ActionFlag, result.Action)
}

func TestTopicBlockGuard_CustomMessage(t *testing.T) {
	cfg := TopicBlockConfig{
		Topics:  []string{"gambling"},
		Message: "Gambling discussion not permitted",
	}
	data, _ := json.Marshal(cfg)

	guard, err := NewTopicBlockGuard(data)
	require.NoError(t, err)

	result, err := guard.Check(context.Background(), &Content{Text: "let's talk about gambling"})
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Equal(t, "Gambling discussion not permitted", result.Reason)
}

func TestTopicBlockGuard_EmptyContent(t *testing.T) {
	cfg := TopicBlockConfig{Topics: []string{"weapons"}}
	data, _ := json.Marshal(cfg)

	guard, err := NewTopicBlockGuard(data)
	require.NoError(t, err)

	result, err := guard.Check(context.Background(), &Content{Text: ""})
	require.NoError(t, err)
	assert.True(t, result.Pass)
}

func TestTopicBlockGuard_Name(t *testing.T) {
	guard, err := NewTopicBlockGuard(nil)
	require.NoError(t, err)
	assert.Equal(t, "topic_block", guard.Name())
}

func TestTopicBlockGuard_Phase(t *testing.T) {
	guard, err := NewTopicBlockGuard(nil)
	require.NoError(t, err)
	assert.Equal(t, PhaseInput, guard.Phase())
}

func TestTopicBlockGuard_Transform(t *testing.T) {
	guard, err := NewTopicBlockGuard(nil)
	require.NoError(t, err)
	content := &Content{Text: "test"}
	result, err := guard.Transform(context.Background(), content)
	require.NoError(t, err)
	assert.Equal(t, content, result)
}

func TestTopicBlockGuard_Registry(t *testing.T) {
	// Verify the guardrail is registered.
	guard, err := Create("topic_block", nil)
	require.NoError(t, err)
	assert.Equal(t, "topic_block", guard.Name())
}

func TestCheckTopicBlock_Standalone(t *testing.T) {
	cfg := TopicBlockConfig{
		Topics: []string{"violence", "hate speech"},
	}

	blocked, topic := CheckTopicBlock("This contains violence", cfg)
	assert.True(t, blocked)
	assert.Equal(t, "violence", topic)

	blocked, topic = CheckTopicBlock("This is a friendly message", cfg)
	assert.False(t, blocked)
	assert.Empty(t, topic)
}
