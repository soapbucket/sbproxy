package maxmind

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTracedManager_Lookup_Success(t *testing.T) {
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

	// Create traced manager
	tracedManager := NewTracedManager(mockManager)
	require.NotNil(t, tracedManager)

	// Test IPv4 lookup
	ipv4 := net.ParseIP("107.210.156.163")
	result, err := tracedManager.Lookup(ipv4)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, mockResult, result)

	// Test IPv6 lookup
	ipv6 := net.ParseIP("2001:4860:7:30e::9b")
	result, err = tracedManager.Lookup(ipv6)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, mockResult, result)
}

func TestTracedManager_Lookup_Error(t *testing.T) {
	t.Parallel()
	// Create mock manager that returns error
	mockManager := &MockManager{
		lookupResult: nil,
		lookupError:  ErrInvalidSettings,
	}

	// Create traced manager
	tracedManager := NewTracedManager(mockManager)
	require.NotNil(t, tracedManager)

	// Test lookup with error
	ip := net.ParseIP("107.210.156.163")
	result, err := tracedManager.Lookup(ip)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, ErrInvalidSettings, err)
}

func TestTracedManager_Close_Success(t *testing.T) {
	t.Parallel()
	// Create mock manager
	mockManager := &MockManager{
		closeError: nil,
	}

	// Create traced manager
	tracedManager := NewTracedManager(mockManager)
	require.NotNil(t, tracedManager)

	// Test close
	err := tracedManager.Close()
	assert.NoError(t, err)
}

func TestTracedManager_Close_Error(t *testing.T) {
	t.Parallel()
	// Create mock manager that returns error
	mockManager := &MockManager{
		closeError: ErrInvalidSettings,
	}

	// Create traced manager
	tracedManager := NewTracedManager(mockManager)
	require.NotNil(t, tracedManager)

	// Test close with error
	err := tracedManager.Close()
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidSettings, err)
}

func TestTracedManager_NilManager(t *testing.T) {
	t.Parallel()
	// Test with nil manager
	tracedManager := NewTracedManager(nil)
	assert.Nil(t, tracedManager)
}

func TestTracedManager_IPVersionDetection(t *testing.T) {
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

	// Create traced manager
	tracedManager := NewTracedManager(mockManager)
	require.NotNil(t, tracedManager)

	// Test IPv4 detection
	ipv4 := net.ParseIP("192.168.1.1")
	result, err := tracedManager.Lookup(ipv4)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Test IPv6 detection
	ipv6 := net.ParseIP("2001:db8::1")
	result, err = tracedManager.Lookup(ipv6)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Test unknown IP version
	invalidIP := net.ParseIP("invalid")
	result, err = tracedManager.Lookup(invalidIP)
	// This should still work, just with unknown IP version
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestTracedManager_ResultAttributes(t *testing.T) {
	t.Parallel()
	// Create mock manager with detailed result
	mockResult := &Result{
		Country:       "United States",
		CountryCode:   "US",
		Continent:     "North America",
		ContinentCode: "NA",
		ASN:           "AS7018",
		ASName:        "AT&T Enterprises, LLC",
		ASDomain:      "att.com",
	}
	mockManager := &MockManager{
		lookupResult: mockResult,
		lookupError:  nil,
	}

	// Create traced manager
	tracedManager := NewTracedManager(mockManager)
	require.NotNil(t, tracedManager)

	// Test lookup with detailed result
	ip := net.ParseIP("107.210.156.163")
	result, err := tracedManager.Lookup(ip)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, mockResult, result)
}
