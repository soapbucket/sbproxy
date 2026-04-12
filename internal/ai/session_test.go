package ai

import (
	"context"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestCacher(t *testing.T) cacher.Cacher {
	t.Helper()
	c, err := cacher.NewMemoryCacher(cacher.Settings{})
	require.NoError(t, err)
	return c
}

func TestSessionTracker_Track(t *testing.T) {
	cache := newTestCacher(t)
	defer cache.Close()

	tracker := NewSessionTracker(cache, 5*time.Minute)
	ctx := context.Background()

	// First request creates a new session
	data, isNew, err := tracker.Track(ctx, "sess-1", "my-agent", "key-1", 100, 0.01)
	require.NoError(t, err)
	assert.True(t, isNew)
	assert.Equal(t, "sess-1", data.SessionID)
	assert.Equal(t, "my-agent", data.Agent)
	assert.Equal(t, "key-1", data.APIKey)
	assert.Equal(t, 1, data.RequestCount)
	assert.Equal(t, 100, data.TotalTokens)
	assert.InDelta(t, 0.01, data.TotalCostUSD, 0.001)

	// Second request updates existing session
	data, isNew, err = tracker.Track(ctx, "sess-1", "my-agent", "key-1", 200, 0.02)
	require.NoError(t, err)
	assert.False(t, isNew)
	assert.Equal(t, 2, data.RequestCount)
	assert.Equal(t, 300, data.TotalTokens)
	assert.InDelta(t, 0.03, data.TotalCostUSD, 0.001)
}

func TestSessionTracker_Get(t *testing.T) {
	cache := newTestCacher(t)
	defer cache.Close()

	tracker := NewSessionTracker(cache, 5*time.Minute)
	ctx := context.Background()

	// Track a session
	_, _, err := tracker.Track(ctx, "sess-2", "agent-b", "", 50, 0.005)
	require.NoError(t, err)

	// Get the session
	data, err := tracker.Get(ctx, "sess-2")
	require.NoError(t, err)
	assert.Equal(t, "sess-2", data.SessionID)
	assert.Equal(t, "agent-b", data.Agent)
	assert.Equal(t, 1, data.RequestCount)

	// Get nonexistent session
	_, err = tracker.Get(ctx, "nonexistent")
	assert.Error(t, err)
}

func TestSessionTracker_DefaultTTL(t *testing.T) {
	cache := newTestCacher(t)
	defer cache.Close()

	tracker := NewSessionTracker(cache, 0)
	assert.Equal(t, time.Hour, tracker.ttl)
}
