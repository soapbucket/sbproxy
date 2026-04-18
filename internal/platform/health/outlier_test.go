package health

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOutlierDetector_RecordSuccess(t *testing.T) {
	od := NewOutlierDetector(OutlierConfig{
		ConsecutiveFailures: 3,
		EjectionDuration:    10 * time.Second,
		MaxEjectedPercent:   0.5,
	})

	od.RecordSuccess("host-a")
	stats := od.Stats()

	require.Contains(t, stats, "host-a")
	assert.Equal(t, int64(1), stats["host-a"].TotalRequests)
	assert.Equal(t, int64(0), stats["host-a"].TotalFailures)
	assert.Equal(t, 0, stats["host-a"].ConsecutiveFailures)
	assert.False(t, stats["host-a"].Ejected)
}

func TestOutlierDetector_EjectsAfterConsecutiveFailures(t *testing.T) {
	od := NewOutlierDetector(OutlierConfig{
		ConsecutiveFailures: 3,
		EjectionDuration:    10 * time.Second,
		MaxEjectedPercent:   0.5,
	})

	// Need at least 2 hosts for ejection to work (never eject the last host)
	od.RecordSuccess("host-b")

	od.RecordFailure("host-a")
	od.RecordFailure("host-a")
	assert.False(t, od.IsEjected("host-a"), "should not eject before threshold")

	od.RecordFailure("host-a")
	assert.True(t, od.IsEjected("host-a"), "should eject after 3 consecutive failures")
}

func TestOutlierDetector_SuccessResetsFailureCount(t *testing.T) {
	od := NewOutlierDetector(OutlierConfig{
		ConsecutiveFailures: 3,
		EjectionDuration:    10 * time.Second,
		MaxEjectedPercent:   0.5,
	})

	od.RecordSuccess("host-b") // Second host so ejection is possible

	od.RecordFailure("host-a")
	od.RecordFailure("host-a")
	od.RecordSuccess("host-a") // Resets consecutive count
	od.RecordFailure("host-a")
	od.RecordFailure("host-a")

	assert.False(t, od.IsEjected("host-a"), "success should reset consecutive failure count")
}

func TestOutlierDetector_MaxEjectedPercent(t *testing.T) {
	od := NewOutlierDetector(OutlierConfig{
		ConsecutiveFailures: 2,
		EjectionDuration:    10 * time.Second,
		MaxEjectedPercent:   0.3, // Max 30% ejected
	})

	// Create 4 hosts
	od.RecordSuccess("host-a")
	od.RecordSuccess("host-b")
	od.RecordSuccess("host-c")
	od.RecordSuccess("host-d")

	// Eject host-a (1/4 = 25%, under 30%)
	od.RecordFailure("host-a")
	od.RecordFailure("host-a")
	assert.True(t, od.IsEjected("host-a"))

	// Try to eject host-b (would be 2/4 = 50%, over 30%)
	od.RecordFailure("host-b")
	od.RecordFailure("host-b")
	assert.False(t, od.IsEjected("host-b"), "should not eject when max percent would be exceeded")
}

func TestOutlierDetector_NeverEjectsLastHost(t *testing.T) {
	od := NewOutlierDetector(OutlierConfig{
		ConsecutiveFailures: 2,
		EjectionDuration:    10 * time.Second,
		MaxEjectedPercent:   1.0, // Even with 100% allowed
	})

	// Only one host
	od.RecordFailure("host-a")
	od.RecordFailure("host-a")

	assert.False(t, od.IsEjected("host-a"), "should never eject the only host")
}

func TestOutlierDetector_CheckRecovery(t *testing.T) {
	od := NewOutlierDetector(OutlierConfig{
		ConsecutiveFailures: 2,
		EjectionDuration:    50 * time.Millisecond,
		MaxEjectedPercent:   0.5,
	})

	od.RecordSuccess("host-b")

	od.RecordFailure("host-a")
	od.RecordFailure("host-a")
	require.True(t, od.IsEjected("host-a"))

	// Wait for ejection duration to pass
	time.Sleep(60 * time.Millisecond)

	od.CheckRecovery()
	assert.False(t, od.IsEjected("host-a"), "host should recover after ejection duration")
}

func TestOutlierDetector_CheckRecovery_ResetsConsecutiveFailures(t *testing.T) {
	od := NewOutlierDetector(OutlierConfig{
		ConsecutiveFailures: 2,
		EjectionDuration:    50 * time.Millisecond,
		MaxEjectedPercent:   0.5,
	})

	od.RecordSuccess("host-b")

	od.RecordFailure("host-a")
	od.RecordFailure("host-a")
	require.True(t, od.IsEjected("host-a"))

	time.Sleep(60 * time.Millisecond)
	od.CheckRecovery()

	// After recovery, one failure should not eject (needs 2 consecutive)
	od.RecordFailure("host-a")
	assert.False(t, od.IsEjected("host-a"))
}

func TestOutlierDetector_IsEjected_UnknownHost(t *testing.T) {
	od := NewOutlierDetector(OutlierConfig{
		ConsecutiveFailures: 3,
	})

	assert.False(t, od.IsEjected("unknown-host"))
}

func TestOutlierDetector_Stats(t *testing.T) {
	od := NewOutlierDetector(OutlierConfig{
		ConsecutiveFailures: 5,
		EjectionDuration:    10 * time.Second,
		MaxEjectedPercent:   0.5,
	})

	od.RecordSuccess("host-a")
	od.RecordSuccess("host-a")
	od.RecordFailure("host-a")
	od.RecordSuccess("host-b")

	stats := od.Stats()
	assert.Len(t, stats, 2)
	assert.Equal(t, int64(3), stats["host-a"].TotalRequests)
	assert.Equal(t, int64(1), stats["host-a"].TotalFailures)
	assert.Equal(t, int64(1), stats["host-b"].TotalRequests)
}

func TestOutlierDetector_DefaultConfig(t *testing.T) {
	// Zero-value config should get sensible defaults
	od := NewOutlierDetector(OutlierConfig{})

	// Should need 5 consecutive failures (default)
	od.RecordSuccess("host-b")
	for i := 0; i < 4; i++ {
		od.RecordFailure("host-a")
	}
	assert.False(t, od.IsEjected("host-a"))

	od.RecordFailure("host-a")
	assert.True(t, od.IsEjected("host-a"))
}
