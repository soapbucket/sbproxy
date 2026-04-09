package maxmind

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockManager is a simple mock for testing
type MockManager struct {
	lookupResult *Result
	lookupError  error
	closeError   error
}

func (m *MockManager) Lookup(ip net.IP) (*Result, error) {
	return m.lookupResult, m.lookupError
}

func (m *MockManager) Close() error {
	return m.closeError
}

func (m *MockManager) Driver() string {
	return "mock"
}

func TestMetricsManager_Lookup_Success(t *testing.T) {
	t.Parallel()
	// Create mock manager
	mockResult := &Result{
		Country:     "United States",
		CountryCode: "US",
		Continent:   "North America",
		ASN:         "AS7018",
		ASName:      "AT&T Enterprises, LLC",
	}
	mockManager := &MockManager{
		lookupResult: mockResult,
		lookupError:  nil,
	}

	// Create metrics manager
	metricsManager := NewMetricsManager(mockManager, "test-driver")
	require.NotNil(t, metricsManager)

	// Test IPv4 lookup
	ipv4 := net.ParseIP("107.210.156.163")
	result, err := metricsManager.Lookup(ipv4)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, mockResult, result)

	// Test IPv6 lookup
	ipv6 := net.ParseIP("2001:4860:7:30e::9b")
	result, err = metricsManager.Lookup(ipv6)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, mockResult, result)
}

func TestMetricsManager_Lookup_Error(t *testing.T) {
	t.Parallel()
	// Create mock manager that returns error
	mockManager := &MockManager{
		lookupResult: nil,
		lookupError:  ErrInvalidSettings,
	}

	// Create metrics manager
	metricsManager := NewMetricsManager(mockManager, "test-driver")
	require.NotNil(t, metricsManager)

	// Test lookup with error
	ip := net.ParseIP("107.210.156.163")
	result, err := metricsManager.Lookup(ip)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, ErrInvalidSettings, err)
}

func TestMetricsManager_Close_Success(t *testing.T) {
	t.Parallel()
	// Create mock manager
	mockManager := &MockManager{
		closeError: nil,
	}

	// Create metrics manager
	metricsManager := NewMetricsManager(mockManager, "test-driver")
	require.NotNil(t, metricsManager)

	// Test close
	err := metricsManager.Close()
	assert.NoError(t, err)
}

func TestMetricsManager_Close_Error(t *testing.T) {
	t.Parallel()
	// Create mock manager that returns error
	mockManager := &MockManager{
		closeError: ErrInvalidSettings,
	}

	// Create metrics manager
	metricsManager := NewMetricsManager(mockManager, "test-driver")
	require.NotNil(t, metricsManager)

	// Test close with error
	err := metricsManager.Close()
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidSettings, err)
}

func TestMetricsManager_NilManager(t *testing.T) {
	t.Parallel()
	// Test with nil manager
	metricsManager := NewMetricsManager(nil, "test-driver")
	assert.Nil(t, metricsManager)
}

func TestMetricsManager_IPVersionDetection(t *testing.T) {
	t.Parallel()
	// Create mock manager
	mockResult := &Result{
		CountryCode: "US",
	}
	mockManager := &MockManager{
		lookupResult: mockResult,
		lookupError:  nil,
	}

	// Create metrics manager
	metricsManager := NewMetricsManager(mockManager, "test-driver")
	require.NotNil(t, metricsManager)

	// Test IPv4 detection
	ipv4 := net.ParseIP("192.168.1.1")
	result, err := metricsManager.Lookup(ipv4)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Test IPv6 detection
	ipv6 := net.ParseIP("2001:db8::1")
	result, err = metricsManager.Lookup(ipv6)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Test unknown IP version
	invalidIP := net.ParseIP("invalid")
	result, err = metricsManager.Lookup(invalidIP)
	// This should still work, just with unknown IP version
	require.NoError(t, err)
	require.NotNil(t, result)
}
