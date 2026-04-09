package maxmind

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMaxMindDriver_CoreBuild(t *testing.T) {
	t.Parallel()
	// In the core build, the maxmind driver is registered but returns ErrNotAvailable.
	settings := Settings{
		Driver: DriverMaxMind,
		Params: map[string]string{
			ParamPath: "/any/path.mmdb",
		},
	}

	manager, err := NewManager(settings)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in core build")
	assert.Nil(t, manager)
}

func TestNoopManager(t *testing.T) {
	t.Parallel()
	t.Run("Lookup", func(t *testing.T) {
		t.Parallel()
		ip := net.ParseIP("107.210.156.163")
		require.NotNil(t, ip)

		result, err := NoopManager.Lookup(ip)
		require.NoError(t, err)
		require.NotNil(t, result)

		// Noop manager should return an empty result
		assert.Equal(t, &Result{}, result)
	})

	t.Run("Close", func(t *testing.T) {
		t.Parallel()
		err := NoopManager.Close()
		assert.NoError(t, err, "Noop manager close should not return an error")
	})
}

func TestNewManager(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		settings    Settings
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil settings",
			settings:    Settings{},
			expectError: false, // Should return NoopManager
		},
		{
			name: "empty driver",
			settings: Settings{
				Driver: "",
			},
			expectError: false, // Should return NoopManager
		},
		{
			name: "unsupported driver",
			settings: Settings{
				Driver: "unsupported",
			},
			expectError: true,
			errorMsg:    "maxmind: unsupported driver",
		},
		{
			name: "noop driver",
			settings: Settings{
				Driver: DriverNoop,
			},
			expectError: false,
		},
		{
			name: "maxmind driver returns not available in core build",
			settings: Settings{
				Driver: DriverMaxMind,
				Params: map[string]string{
					ParamPath: "/any/path.mmdb",
				},
			},
			expectError: true,
			errorMsg:    "not available in core build",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewManager(tt.settings)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				assert.Nil(t, manager)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, manager)
				if manager != NoopManager {
					defer manager.Close()
				}
			}
		})
	}
}

func TestAvailableDrivers(t *testing.T) {
	t.Parallel()
	drivers := AvailableDrivers()

	// Should include at least the registered drivers
	assert.Contains(t, drivers, DriverNoop)
	assert.Contains(t, drivers, DriverMaxMind)

	t.Logf("Available drivers: %v", drivers)
}

func TestDriverRegistration(t *testing.T) {
	t.Parallel()
	// Test that drivers are properly registered
	drivers := AvailableDrivers()
	assert.GreaterOrEqual(t, len(drivers), 2, "Should have at least 2 drivers registered")
}

func TestConstants(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "noop", DriverNoop)
	assert.Equal(t, "maxmind", DriverMaxMind)
	assert.Equal(t, "path", ParamPath)
	assert.Equal(t, int64(5*60*1000000000), int64(DefaultCacheDuration)) // 5 minutes in nanoseconds
}

func TestErrors(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "maxmind: unsupported driver", ErrUnsupportedDriver.Error())
	assert.Equal(t, "maxmind: invalid settings", ErrInvalidSettings.Error())
}

// createTestManager returns a noop manager for the core build.
// In the enterprise build this would return a real maxmind manager
// backed by a fixture database.
func createTestManager(t *testing.T) Manager {
	t.Helper()
	return NoopManager
}
