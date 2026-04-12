package health

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVaultChecker_Name(t *testing.T) {
	vc := NewVaultChecker()
	assert.Equal(t, "vault", vc.Name())
}

func TestVaultChecker_NotConfigured(t *testing.T) {
	vc := NewVaultChecker()
	status, err := vc.Check()
	require.NoError(t, err)
	assert.Equal(t, "ok", status)
	assert.False(t, vc.IsConfigured())
}

func TestVaultChecker_ConfiguredButNeverResolved(t *testing.T) {
	vc := NewVaultChecker()
	vc.SetConfigured(true)

	status, err := vc.Check()
	assert.Error(t, err)
	assert.Empty(t, status)
	assert.Contains(t, err.Error(), "never been resolved")
}

func TestVaultChecker_Healthy(t *testing.T) {
	vc := NewVaultChecker()
	vc.SetConfigured(true)
	vc.RecordResolution(5, time.Now())

	status, err := vc.Check()
	require.NoError(t, err)
	assert.Equal(t, "ok", status)
	assert.Equal(t, 5, vc.CachedSecretCount())
	assert.True(t, vc.IsConfigured())
}

func TestVaultChecker_DegradedStaleSecrets(t *testing.T) {
	vc := NewVaultChecker(WithMaxSecretAge(1 * time.Hour))
	vc.SetConfigured(true)

	// Record resolution with an oldest secret that is 2 hours old.
	oldTime := time.Now().Add(-2 * time.Hour)
	vc.RecordResolution(3, oldTime)

	status, err := vc.Check()
	require.NoError(t, err)
	assert.Equal(t, "degraded", status)
}

func TestVaultChecker_FreshSecrets(t *testing.T) {
	vc := NewVaultChecker(WithMaxSecretAge(1 * time.Hour))
	vc.SetConfigured(true)

	// Record resolution with a recent oldest secret.
	vc.RecordResolution(3, time.Now().Add(-30*time.Minute))

	status, err := vc.Check()
	require.NoError(t, err)
	assert.Equal(t, "ok", status)
}

func TestVaultChecker_ZeroCachedSecrets(t *testing.T) {
	vc := NewVaultChecker()
	vc.SetConfigured(true)
	vc.RecordResolution(0, time.Time{})

	status, err := vc.Check()
	require.NoError(t, err)
	assert.Equal(t, "ok", status)
}

func TestVaultChecker_LastResolutionTime(t *testing.T) {
	vc := NewVaultChecker()
	assert.True(t, vc.LastResolutionTime().IsZero())

	vc.RecordResolution(1, time.Now())
	assert.False(t, vc.LastResolutionTime().IsZero())
}

func TestVaultChecker_OldestSecretAge(t *testing.T) {
	vc := NewVaultChecker()
	assert.Equal(t, time.Duration(0), vc.OldestSecretAge())

	oldTime := time.Now().Add(-10 * time.Minute)
	vc.RecordResolution(1, oldTime)

	age := vc.OldestSecretAge()
	assert.True(t, age >= 10*time.Minute, "expected age >= 10m, got %s", age)
}

func TestVaultChecker_Details(t *testing.T) {
	vc := NewVaultChecker()
	vc.SetConfigured(true)

	oldTime := time.Now().Add(-5 * time.Minute)
	vc.RecordResolution(7, oldTime)

	details := vc.Details()
	assert.Equal(t, true, details["configured"])
	assert.Equal(t, 7, details["cached_count"])
	assert.NotEmpty(t, details["last_resolution"])
	assert.NotEmpty(t, details["oldest_secret_age"])
}

func TestVaultChecker_DetailsNotConfigured(t *testing.T) {
	vc := NewVaultChecker()
	details := vc.Details()
	assert.Equal(t, false, details["configured"])
	assert.Equal(t, 0, details["cached_count"])
	_, hasLastResolution := details["last_resolution"]
	assert.False(t, hasLastResolution)
}

func TestVaultChecker_RegisterWithManager(t *testing.T) {
	mgr := &Manager{
		checkers:  make(map[string]Checker),
		startTime: time.Now(),
	}

	vc := NewVaultChecker()
	vc.SetConfigured(true)
	vc.RecordResolution(3, time.Now())

	mgr.RegisterChecker(vc)

	status := mgr.GetStatus()
	assert.Equal(t, "ok", status.Status)
	assert.Equal(t, "ok", status.Checks["vault"])
}

func TestVaultChecker_RegisterDegradedAffectsOverall(t *testing.T) {
	mgr := &Manager{
		checkers:  make(map[string]Checker),
		startTime: time.Now(),
	}

	vc := NewVaultChecker(WithMaxSecretAge(1 * time.Hour))
	vc.SetConfigured(true)
	vc.RecordResolution(3, time.Now().Add(-2*time.Hour))

	mgr.RegisterChecker(vc)

	status := mgr.GetStatus()
	assert.Equal(t, "degraded", status.Status)
	assert.Equal(t, "degraded", status.Checks["vault"])
}

func TestVaultChecker_ConcurrentAccess(t *testing.T) {
	vc := NewVaultChecker()
	vc.SetConfigured(true)

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			vc.RecordResolution(id, time.Now().Add(-time.Duration(id)*time.Minute))
			_, _ = vc.Check()
			_ = vc.Details()
			_ = vc.CachedSecretCount()
			_ = vc.OldestSecretAge()
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// Should not panic; final state is valid.
	status, err := vc.Check()
	require.NoError(t, err)
	assert.NotEmpty(t, status)
}
