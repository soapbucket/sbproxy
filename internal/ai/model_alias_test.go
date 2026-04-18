package ai

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestModelAliasMap_Resolve(t *testing.T) {
	m := NewModelAliasMap(map[string]string{
		"fast":   "gpt-4o-mini",
		"smart":  "gpt-4o",
		"claude": "claude-sonnet-4-20250514",
	})

	assert.Equal(t, "gpt-4o-mini", m.Resolve("fast"))
	assert.Equal(t, "gpt-4o", m.Resolve("smart"))
	assert.Equal(t, "claude-sonnet-4-20250514", m.Resolve("claude"))
	// Unknown alias returns input unchanged.
	assert.Equal(t, "gpt-4-turbo", m.Resolve("gpt-4-turbo"))
}

func TestModelAliasMap_ReverseResolve(t *testing.T) {
	m := NewModelAliasMap(map[string]string{
		"fast":  "gpt-4o-mini",
		"smart": "gpt-4o",
	})

	assert.Equal(t, "fast", m.ReverseResolve("gpt-4o-mini"))
	assert.Equal(t, "smart", m.ReverseResolve("gpt-4o"))
	// Unknown model ID returns input unchanged.
	assert.Equal(t, "gpt-4-turbo", m.ReverseResolve("gpt-4-turbo"))
}

func TestModelAliasMap_Add(t *testing.T) {
	m := NewModelAliasMap(map[string]string{})

	m.Add("fast", "gpt-4o-mini")
	assert.Equal(t, "gpt-4o-mini", m.Resolve("fast"))
	assert.Equal(t, "fast", m.ReverseResolve("gpt-4o-mini"))

	// Update existing alias to point to a different model.
	m.Add("fast", "gpt-4o")
	assert.Equal(t, "gpt-4o", m.Resolve("fast"))
	assert.Equal(t, "fast", m.ReverseResolve("gpt-4o"))
	// Old reverse mapping should be cleaned up.
	assert.Equal(t, "gpt-4o-mini", m.ReverseResolve("gpt-4o-mini"))
}

func TestModelAliasMap_Remove(t *testing.T) {
	m := NewModelAliasMap(map[string]string{
		"fast": "gpt-4o-mini",
	})

	assert.True(t, m.Remove("fast"))
	assert.Equal(t, "fast", m.Resolve("fast"))
	assert.Equal(t, "gpt-4o-mini", m.ReverseResolve("gpt-4o-mini"))

	// Removing non-existent alias returns false.
	assert.False(t, m.Remove("nonexistent"))
}

func TestModelAliasMap_List(t *testing.T) {
	original := map[string]string{
		"fast":  "gpt-4o-mini",
		"smart": "gpt-4o",
	}
	m := NewModelAliasMap(original)

	listed := m.List()
	assert.Equal(t, original, listed)

	// Verify it returns a copy (modifying listed should not affect internal state).
	listed["new"] = "new-model"
	assert.Equal(t, 2, len(m.List()))
}

func TestModelAliasMap_EmptyMap(t *testing.T) {
	m := NewModelAliasMap(nil)
	assert.Equal(t, "gpt-4o", m.Resolve("gpt-4o"))
	assert.Equal(t, "gpt-4o", m.ReverseResolve("gpt-4o"))
	assert.Empty(t, m.List())
}
