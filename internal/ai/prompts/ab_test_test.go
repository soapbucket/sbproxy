package prompts

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestABSelector_Select(t *testing.T) {
	cfg := &ABTestConfig{
		Variants: []ABTestVariant{
			{PromptID: "v1", Weight: 70},
			{PromptID: "v2", Weight: 30},
		},
	}
	sel := NewABSelector(cfg)

	// Run many selections and verify distribution is roughly correct
	counts := map[string]int{}
	for i := 0; i < 1000; i++ {
		v, idx := sel.Select("")
		require.NotNil(t, v)
		assert.True(t, idx >= 0 && idx <= 1)
		counts[v.PromptID]++
	}

	// Should be roughly 70/30 (with some tolerance)
	assert.True(t, counts["v1"] > 500, "v1 count %d should be > 500", counts["v1"])
	assert.True(t, counts["v2"] > 100, "v2 count %d should be > 100", counts["v2"])
}

func TestABSelector_ConsistentSession(t *testing.T) {
	cfg := &ABTestConfig{
		Variants: []ABTestVariant{
			{PromptID: "v1", Weight: 50},
			{PromptID: "v2", Weight: 50},
		},
	}
	sel := NewABSelector(cfg)

	// Same session should always get the same variant
	first, _ := sel.Select("session-123")
	for i := 0; i < 100; i++ {
		v, _ := sel.Select("session-123")
		assert.Equal(t, first.PromptID, v.PromptID)
	}
}

func TestABSelector_Resolve(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	err := store.Create(ctx, &Prompt{
		ID:            "welcome-v1",
		Name:          "Welcome V1",
		ActiveVersion: 1,
		Versions:      []LegacyVersion{{Version: 1, Template: "Hello from V1"}},
	})
	require.NoError(t, err)

	err = store.Create(ctx, &Prompt{
		ID:            "welcome-v2",
		Name:          "Welcome V2",
		ActiveVersion: 1,
		Versions:      []LegacyVersion{{Version: 1, Template: "Hello from V2"}},
	})
	require.NoError(t, err)

	cfg := &ABTestConfig{
		Variants: []ABTestVariant{
			{PromptID: "welcome-v1", Weight: 100},
		},
	}
	sel := NewABSelector(cfg)

	resolved, result, err := sel.Resolve(ctx, store, "")
	require.NoError(t, err)
	assert.Equal(t, "Hello from V1", resolved.Content)
	assert.Equal(t, "welcome-v1", result.PromptID)
	assert.Equal(t, 0, result.Variant)
}

func TestABSelector_Empty(t *testing.T) {
	sel := NewABSelector(nil)
	v, idx := sel.Select("")
	assert.Nil(t, v)
	assert.Equal(t, -1, idx)
}
