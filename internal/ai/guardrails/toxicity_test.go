package guardrails

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToxicity_SafeContent(t *testing.T) {
	g, err := NewToxicityFilter(nil)
	require.NoError(t, err)

	content := testContent("The weather is nice today")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass)
}

func TestToxicity_ViolentContent(t *testing.T) {
	g, err := NewToxicityFilter(nil)
	require.NoError(t, err)

	content := testContent("I'll kill them all for this")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Contains(t, result.Details["categories"], "violence")
}

func TestToxicity_ThreatContent(t *testing.T) {
	g, err := NewToxicityFilter(nil)
	require.NoError(t, err)

	content := testContent("I'm going to attack you for saying that")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)
}

func TestToxicity_SelfHarm(t *testing.T) {
	g, err := NewToxicityFilter(nil)
	require.NoError(t, err)

	content := testContent("how to commit suicide")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Contains(t, result.Details["categories"], "self_harm")
}

func TestToxicity_CustomThreshold(t *testing.T) {
	g, err := NewToxicityFilter(json.RawMessage(`{"threshold": 0.99}`))
	require.NoError(t, err)

	// This would normally be caught but threshold is very high
	content := testContent("You're worthless")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass) // Below 0.99 threshold
}

func TestToxicity_CategoryFilter(t *testing.T) {
	g, err := NewToxicityFilter(json.RawMessage(`{"categories": ["violence"]}`))
	require.NoError(t, err)

	// Should not detect harassment when only checking violence
	content := testContent("You are pathetic and worthless")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass)
}

func TestToxicity_EmptyContent(t *testing.T) {
	g, err := NewToxicityFilter(nil)
	require.NoError(t, err)

	content := &Content{}
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass)
}

func TestToxicity_Name(t *testing.T) {
	g, err := NewToxicityFilter(nil)
	require.NoError(t, err)
	assert.Equal(t, "toxicity", g.Name())
	assert.Equal(t, PhaseOutput, g.Phase())
}
