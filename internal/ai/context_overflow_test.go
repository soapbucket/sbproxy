package ai

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckContextOverflow_WithinLimit(t *testing.T) {
	estimated, max, overflow := CheckContextOverflow("gpt-4o", 50000)
	assert.Equal(t, 50000, estimated)
	assert.Equal(t, 128000, max)
	assert.False(t, overflow)
}

func TestCheckContextOverflow_ExceedsLimit(t *testing.T) {
	estimated, max, overflow := CheckContextOverflow("gpt-4", 10000)
	assert.Equal(t, 10000, estimated)
	assert.Equal(t, 8192, max)
	assert.True(t, overflow)
}

func TestCheckContextOverflow_ExactLimit(t *testing.T) {
	estimated, max, overflow := CheckContextOverflow("gpt-4", 8192)
	assert.Equal(t, 8192, estimated)
	assert.Equal(t, 8192, max)
	assert.False(t, overflow)
}

func TestCheckContextOverflow_UnknownModel(t *testing.T) {
	estimated, max, overflow := CheckContextOverflow("unknown-model", 999999)
	assert.Equal(t, 999999, estimated)
	assert.Equal(t, 0, max)
	assert.False(t, overflow, "unknown models should not report overflow")
}

func TestCheckContextOverflow_LargeModel(t *testing.T) {
	estimated, max, overflow := CheckContextOverflow("gemini-1.5-pro", 1500000)
	assert.Equal(t, 1500000, estimated)
	assert.Equal(t, 2000000, max)
	assert.False(t, overflow)
}

func TestSuggestFallbackModel_NeedLarger(t *testing.T) {
	model, found := SuggestFallbackModel("gpt-4", 10000)
	assert.True(t, found)
	// Should suggest a model with context >= 10000 that is not gpt-4.
	limit, ok := ModelContextLimits[model]
	assert.True(t, ok)
	assert.GreaterOrEqual(t, limit, 10000)
	assert.NotEqual(t, "gpt-4", model)
}

func TestSuggestFallbackModel_AlreadyFits(t *testing.T) {
	model, found := SuggestFallbackModel("gpt-4o", 50000)
	assert.True(t, found)
	assert.Equal(t, "gpt-4o", model)
}

func TestSuggestFallbackModel_NothingBigEnough(t *testing.T) {
	model, found := SuggestFallbackModel("gemini-1.5-pro", 999999999)
	assert.False(t, found)
	assert.Empty(t, model)
}

func TestSuggestFallbackModel_UnknownModel(t *testing.T) {
	model, found := SuggestFallbackModel("nonexistent", 10000)
	assert.True(t, found)
	// Should find some model that fits.
	limit, ok := ModelContextLimits[model]
	assert.True(t, ok)
	assert.GreaterOrEqual(t, limit, 10000)
}

func TestModelContextLimits_KnownModels(t *testing.T) {
	// Verify key models are present.
	assert.Contains(t, ModelContextLimits, "gpt-4o")
	assert.Contains(t, ModelContextLimits, "gpt-4")
	assert.Contains(t, ModelContextLimits, "claude-sonnet-4-20250514")
	assert.Contains(t, ModelContextLimits, "gemini-1.5-pro")

	// Verify reasonable values.
	assert.Equal(t, 128000, ModelContextLimits["gpt-4o"])
	assert.Equal(t, 8192, ModelContextLimits["gpt-4"])
	assert.Equal(t, 2000000, ModelContextLimits["gemini-1.5-pro"])
}
