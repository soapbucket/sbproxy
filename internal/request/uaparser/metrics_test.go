package uaparser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMetricsManager(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		manager     Manager
		driver      string
		expectError bool
	}{
		{
			name:        "nil manager",
			manager:     nil,
			driver:      "test",
			expectError: false, // Should return nil
		},
		{
			name:        "valid manager",
			manager:     NoopManager,
			driver:      "test",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metricsManager := NewMetricsManager(tt.manager, tt.driver)

			if tt.expectError {
				assert.Nil(t, metricsManager)
			} else {
				if tt.manager == nil {
					assert.Nil(t, metricsManager)
				} else {
					assert.NotNil(t, metricsManager)
				}
			}
		})
	}
}

func TestMetricsManager_Parse(t *testing.T) {
	t.Parallel()
	manager := createTestManager(t)
	defer manager.Close()

	metricsManager := NewMetricsManager(manager, "test")
	require.NotNil(t, metricsManager)

	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

	result, err := metricsManager.Parse(userAgent)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should return the same result as the underlying manager
	expectedResult, err := manager.Parse(userAgent)
	require.NoError(t, err)
	assert.Equal(t, expectedResult, result)
}

func TestMetricsManager_Close(t *testing.T) {
	t.Parallel()
	manager := createTestManager(t)
	defer manager.Close()

	metricsManager := NewMetricsManager(manager, "test")
	require.NotNil(t, metricsManager)

	err := metricsManager.Close()
	assert.NoError(t, err, "Close should not return an error")
}
