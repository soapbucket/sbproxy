package guardrails

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegexGuard_Deny(t *testing.T) {
	g, err := NewRegexGuard(json.RawMessage(`{"deny": ["password\\s*=", "secret_key"]}`))
	require.NoError(t, err)

	content := testContent("Set password = admin123")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Contains(t, result.Reason, "deny pattern")
}

func TestRegexGuard_DenyNoMatch(t *testing.T) {
	g, err := NewRegexGuard(json.RawMessage(`{"deny": ["forbidden"]}`))
	require.NoError(t, err)

	content := testContent("This is perfectly fine text")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass)
}

func TestRegexGuard_Allow(t *testing.T) {
	g, err := NewRegexGuard(json.RawMessage(`{
		"deny": ["dangerous"],
		"allow": ["safe_context"]
	}`))
	require.NoError(t, err)

	// Allow pattern overrides deny
	content := testContent("This safe_context contains dangerous content")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass)
}

func TestRegexGuard_MultipleDeny(t *testing.T) {
	g, err := NewRegexGuard(json.RawMessage(`{"deny": ["bad", "evil"]}`))
	require.NoError(t, err)

	content := testContent("This is bad and evil")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)

	matched := result.Details["matched_patterns"].([]string)
	assert.Len(t, matched, 2)
}

func TestRegexGuard_Empty(t *testing.T) {
	g, err := NewRegexGuard(nil)
	require.NoError(t, err)

	content := testContent("Anything goes")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass)
}

func TestRegexGuard_EmptyContent(t *testing.T) {
	g, err := NewRegexGuard(json.RawMessage(`{"deny": ["test"]}`))
	require.NoError(t, err)

	content := &Content{}
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass)
}

func TestRegexGuard_InvalidPattern(t *testing.T) {
	_, err := NewRegexGuard(json.RawMessage(`{"deny": ["[invalid"]}`))
	assert.Error(t, err)
}

func TestRegexGuard_Name(t *testing.T) {
	g, err := NewRegexGuard(nil)
	require.NoError(t, err)
	assert.Equal(t, "regex_guard", g.Name())
	assert.Equal(t, PhaseInput, g.Phase())
}
