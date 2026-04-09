package uaparser

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCachedManager(t *testing.T) {
	t.Parallel()
	manager := createTestManager(t)
	defer manager.Close()

	tests := []struct {
		name        string
		manager     Manager
		duration    time.Duration
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil manager",
			manager:     nil,
			duration:    DefaultCacheDuration,
			expectError: true,
		},
		{
			name:        "valid manager with default duration",
			manager:     manager,
			duration:    0, // Should use default
			expectError: false,
		},
		{
			name:        "valid manager with custom duration",
			manager:     manager,
			duration:    1 * time.Minute,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cachedManager, err := NewCachedManager(tt.manager, tt.duration)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				assert.Nil(t, cachedManager)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cachedManager)
				if cachedManager != nil {
					defer cachedManager.Close()
				}
			}
		})
	}
}

func TestCachedManager_Parse_CacheHit(t *testing.T) {
	t.Parallel()
	manager := createTestManager(t)
	defer manager.Close()

	cachedManager, err := NewCachedManager(manager, 1*time.Minute)
	require.NoError(t, err)
	defer cachedManager.Close()

	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

	// First parse - should miss cache
	result1, err := cachedManager.Parse(userAgent)
	require.NoError(t, err)
	require.NotNil(t, result1)

	// Wait for async cache update to complete
	time.Sleep(100 * time.Millisecond)

	// Second parse - should hit cache
	result2, err := cachedManager.Parse(userAgent)
	require.NoError(t, err)
	require.NotNil(t, result2)

	// Results should be the same
	assert.Equal(t, result1, result2)
}

func TestCachedManager_Parse_CacheMiss(t *testing.T) {
	t.Parallel()
	manager := createTestManager(t)
	defer manager.Close()

	cachedManager, err := NewCachedManager(manager, 1*time.Minute)
	require.NoError(t, err)
	defer cachedManager.Close()

	userAgent1 := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	userAgent2 := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"

	// Parse different user agents
	result1, err := cachedManager.Parse(userAgent1)
	require.NoError(t, err)
	require.NotNil(t, result1)

	result2, err := cachedManager.Parse(userAgent2)
	require.NoError(t, err)
	require.NotNil(t, result2)

	// Results should be different
	assert.NotEqual(t, result1, result2)
}

func TestCachedManager_Close(t *testing.T) {
	t.Parallel()
	manager := createTestManager(t)
	defer manager.Close()

	cachedManager, err := NewCachedManager(manager, 1*time.Minute)
	require.NoError(t, err)

	err = cachedManager.Close()
	assert.NoError(t, err, "Close should not return an error")

	// Test that we can close multiple times without issues
	err = cachedManager.Close()
	assert.NoError(t, err, "Multiple close calls should not return an error")
}
