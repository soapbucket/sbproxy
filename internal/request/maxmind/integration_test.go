package maxmind

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManager_WithMetrics_CoreBuild(t *testing.T) {
	t.Parallel()
	// In the core build, maxmind driver returns ErrNotAvailable.
	settings := Settings{
		Driver:        DriverMaxMind,
		EnableMetrics: true,
		Params: map[string]string{
			ParamPath: "/any/path.mmdb",
		},
	}

	manager, err := NewManager(settings)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in core build")
	assert.Nil(t, manager)
}

func TestNewManager_NoopDriver_WithWrappers(t *testing.T) {
	t.Parallel()
	settings := Settings{
		Driver:        DriverNoop,
		EnableMetrics: true,
		EnableTracing: true,
	}

	manager, err := NewManager(settings)
	require.NoError(t, err)
	require.NotNil(t, manager)
	defer manager.Close()

	// Test that wrappers are applied to noop manager
	ip := net.ParseIP("107.210.156.163")
	result, err := manager.Lookup(ip)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, &Result{}, result)
}

func TestNewManager_ErrorHandling(t *testing.T) {
	t.Parallel()
	// Test with invalid driver
	settings := Settings{
		Driver:        "invalid",
		EnableMetrics: true,
		EnableTracing: true,
	}

	manager, err := NewManager(settings)
	assert.Error(t, err)
	assert.Nil(t, manager)
	assert.Equal(t, ErrUnsupportedDriver, err)
}

func TestNewManager_NilSettings(t *testing.T) {
	t.Parallel()
	// Test with empty settings
	manager, err := NewManager(Settings{})
	require.NoError(t, err)
	require.NotNil(t, manager)
	assert.Equal(t, NoopManager, manager)
}

func TestNewManager_EmptyDriver(t *testing.T) {
	t.Parallel()
	// Test with empty driver
	settings := Settings{
		Driver: "",
	}

	manager, err := NewManager(settings)
	require.NoError(t, err)
	require.NotNil(t, manager)
	assert.Equal(t, NoopManager, manager)
}
