package uaparser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTracedManager(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		manager     Manager
		expectError bool
	}{
		{
			name:        "nil manager",
			manager:     nil,
			expectError: false, // Should return nil
		},
		{
			name:        "valid manager",
			manager:     NoopManager,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracedManager := NewTracedManager(tt.manager)

			if tt.expectError {
				assert.Nil(t, tracedManager)
			} else {
				if tt.manager == nil {
					assert.Nil(t, tracedManager)
				} else {
					assert.NotNil(t, tracedManager)
				}
			}
		})
	}
}

func TestTracedManager_Parse(t *testing.T) {
	t.Parallel()
	manager := createTestManager(t)
	defer manager.Close()

	tracedManager := NewTracedManager(manager)
	require.NotNil(t, tracedManager)

	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

	result, err := tracedManager.Parse(userAgent)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should return the same result as the underlying manager
	expectedResult, err := manager.Parse(userAgent)
	require.NoError(t, err)
	assert.Equal(t, expectedResult, result)
}

func TestTracedManager_Close(t *testing.T) {
	t.Parallel()
	manager := createTestManager(t)
	defer manager.Close()

	tracedManager := NewTracedManager(manager)
	require.NotNil(t, tracedManager)

	err := tracedManager.Close()
	assert.NoError(t, err, "Close should not return an error")
}

func TestGetStringValue(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		ptr      interface{}
		field    string
		expected string
	}{
		{
			name:     "nil pointer",
			ptr:      nil,
			field:    "Family",
			expected: "unknown",
		},
		{
			name:     "invalid type",
			ptr:      "not a struct",
			field:    "Family",
			expected: "unknown",
		},
		{
			name:     "invalid field",
			ptr:      NoopManager,
			field:    "InvalidField",
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getStringValue(tt.ptr, tt.field)
			assert.Equal(t, tt.expected, result)
		})
	}
}
