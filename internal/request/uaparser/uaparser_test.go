package uaparser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUAParserManager(t *testing.T) {
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
			expectError: true,
			errorMsg:    "uaparser: invalid settings",
		},
		{
			name: "missing regex_file parameter",
			settings: Settings{
				Driver: DriverUAParser,
				Params: map[string]string{},
			},
			expectError: true,
			errorMsg:    "uaparser: invalid settings",
		},
		{
			name: "invalid regex file path",
			settings: Settings{
				Driver: DriverUAParser,
				Params: map[string]string{
					ParamRegexFile: "/nonexistent/path.yaml",
				},
			},
			expectError: true,
		},
		{
			name: "valid settings with fixture regex file",
			settings: Settings{
				Driver: DriverUAParser,
				Params: map[string]string{
					ParamRegexFile: getFixturePath(t),
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewUAParserManager(tt.settings)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				assert.Nil(t, manager)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, manager)
				defer manager.Close()
			}
		})
	}
}

func TestManager_Parse_ValidUserAgent(t *testing.T) {
	t.Parallel()
	manager := createTestManager(t)
	defer manager.Close()

	// Test with a common user agent string
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

	result, err := manager.Parse(userAgent)
	require.NoError(t, err, "User agent parsing should succeed")
	require.NotNil(t, result, "Result should not be nil")

	// Verify that we got some meaningful data back
	t.Logf("User agent parsing result: %+v", result)

	// At minimum, we should have a non-empty result structure
	assert.NotEmpty(t, result, "Result should not be empty")

	// Check that we have parsed data
	if result.UserAgent != nil {
		assert.NotEmpty(t, result.UserAgent.Family, "Browser family should not be empty")
	}
	if result.OS != nil {
		assert.NotEmpty(t, result.OS.Family, "OS family should not be empty")
	}
	if result.Device != nil {
		assert.NotEmpty(t, result.Device.Family, "Device family should not be empty")
	}
}

func TestManager_Parse_EmptyUserAgent(t *testing.T) {
	t.Parallel()
	manager := createTestManager(t)
	defer manager.Close()

	// Test with an empty user agent string
	result, err := manager.Parse("")
	require.NoError(t, err, "Empty user agent parsing should succeed")
	require.NotNil(t, result, "Result should not be nil")

	// Should return empty result
	assert.NotNil(t, result, "Result should not be nil")
}

func TestManager_Parse_InvalidUserAgent(t *testing.T) {
	t.Parallel()
	manager := createTestManager(t)
	defer manager.Close()

	// Test with a malformed user agent string
	userAgent := "This is not a valid user agent string"
	result, err := manager.Parse(userAgent)

	// Should not error, but may return empty or default values
	require.NoError(t, err, "Invalid user agent parsing should not error")
	require.NotNil(t, result, "Result should not be nil")

	t.Logf("Invalid user agent parsing result: %+v", result)
}

func TestManager_Close(t *testing.T) {
	t.Parallel()
	manager := createTestManager(t)

	err := manager.Close()
	assert.NoError(t, err, "Close should not return an error")

	// Test that we can close multiple times without issues
	err = manager.Close()
	assert.NoError(t, err, "Multiple close calls should not return an error")
}

func TestNoopManager(t *testing.T) {
	t.Parallel()
	t.Run("Parse", func(t *testing.T) {
		t.Parallel()
		userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
		require.NotEmpty(t, userAgent)

		result, err := NoopManager.Parse(userAgent)
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
			errorMsg:    "uaparser: unsupported driver",
		},
		{
			name: "noop driver",
			settings: Settings{
				Driver: DriverNoop,
			},
			expectError: false,
		},
		{
			name: "uaparser driver with valid regex file",
			settings: Settings{
				Driver: DriverUAParser,
				Params: map[string]string{
					ParamRegexFile: getFixturePath(t),
				},
			},
			expectError: false,
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
	assert.Contains(t, drivers, DriverUAParser)

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
	assert.Equal(t, "uaparser", DriverUAParser)
	assert.Equal(t, "path", ParamRegexFile)
	assert.Equal(t, int64(5*60*1000000000), int64(DefaultCacheDuration)) // 5 minutes in nanoseconds
}

func TestErrors(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "uaparser: unsupported driver", ErrUnsupportedDriver.Error())
	assert.Equal(t, "uaparser: invalid settings", ErrInvalidSettings.Error())
}

// Helper function to get the path to the fixture regex file
func getFixturePath(t *testing.T) string {
	t.Helper()
	// Get the current working directory and navigate to the fixture
	wd, err := os.Getwd()
	require.NoError(t, err)

	// Navigate up to the uaparser package directory and then to fixtures
	fixturePath := filepath.Join(wd, "fixtures", "regexes.yaml")

	// Check if the file exists
	_, err = os.Stat(fixturePath)
	require.NoError(t, err, "Fixture regex file should exist at %s", fixturePath)

	return fixturePath
}

// Helper function to create a test manager
func createTestManager(t *testing.T) Manager {
	t.Helper()
	settings := Settings{
		Driver: DriverUAParser,
		Params: map[string]string{
			ParamRegexFile: getFixturePath(t),
		},
	}

	manager, err := NewUAParserManager(settings)
	require.NoError(t, err)
	require.NotNil(t, manager)

	return manager
}
