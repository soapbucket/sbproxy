package keys

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUsageTracker_Record(t *testing.T) {
	tracker := NewUsageTracker()

	tracker.Record("key-1", 100, 50, 0.001, false)
	tracker.Record("key-1", 200, 100, 0.002, false)
	tracker.Record("key-1", 50, 25, 0.0005, true)

	usage := tracker.GetUsage("key-1")
	assert.Equal(t, int64(3), usage.Requests)
	assert.Equal(t, int64(350), usage.InputTokens)
	assert.Equal(t, int64(175), usage.OutputTokens)
	assert.Equal(t, int64(525), usage.TotalTokens)
	assert.InDelta(t, 0.0035, usage.CostUSD, 0.0001)
	assert.Equal(t, int64(1), usage.Errors)
}

func TestUsageTracker_CheckBudget(t *testing.T) {
	tracker := NewUsageTracker()

	// No usage yet - within budget
	assert.True(t, tracker.CheckBudget("key-1", 1.0, "daily"))

	// Record some usage
	tracker.Record("key-1", 1000, 500, 0.5, false)
	assert.True(t, tracker.CheckBudget("key-1", 1.0, "daily"))

	// Exceed budget
	tracker.Record("key-1", 1000, 500, 0.6, false)
	assert.False(t, tracker.CheckBudget("key-1", 1.0, "daily"))

	// No budget limit
	assert.True(t, tracker.CheckBudget("key-1", 0, "daily"))
}

func TestUsageTracker_GetUsageEmpty(t *testing.T) {
	tracker := NewUsageTracker()
	usage := tracker.GetUsage("nonexistent")
	assert.Equal(t, int64(0), usage.Requests)
	assert.Equal(t, "nonexistent", usage.KeyID)
}

func TestUsageTracker_Reset(t *testing.T) {
	tracker := NewUsageTracker()
	tracker.Record("key-1", 100, 50, 0.001, false)
	tracker.Reset("key-1")
	usage := tracker.GetUsage("key-1")
	assert.Equal(t, int64(0), usage.Requests)
}
