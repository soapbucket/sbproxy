package service

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDrainer_IncrementDecrement(t *testing.T) {
	d := NewDrainer()

	assert.Equal(t, int64(0), d.ActiveCount())

	d.Increment()
	d.Increment()
	d.Increment()
	assert.Equal(t, int64(3), d.ActiveCount())

	d.Decrement()
	assert.Equal(t, int64(2), d.ActiveCount())
}

func TestDrainer_IsDraining(t *testing.T) {
	d := NewDrainer()
	assert.False(t, d.IsDraining())

	d.Increment()

	go func() {
		time.Sleep(50 * time.Millisecond)
		d.Decrement()
	}()

	err := d.StartDrain(context.Background(), time.Second)
	require.NoError(t, err)
	assert.True(t, d.IsDraining())
}

func TestDrainer_DrainsImmediately_WhenNoActive(t *testing.T) {
	d := NewDrainer()

	start := time.Now()
	err := d.StartDrain(context.Background(), time.Second)
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Less(t, elapsed, 100*time.Millisecond, "should drain immediately when no active requests")
}

func TestDrainer_WaitsForActiveRequests(t *testing.T) {
	d := NewDrainer()

	d.Increment()
	d.Increment()

	var drainErr error
	drainDone := make(chan struct{})

	go func() {
		drainErr = d.StartDrain(context.Background(), 5*time.Second)
		close(drainDone)
	}()

	// Wait a bit, then finish requests
	time.Sleep(50 * time.Millisecond)
	d.Decrement()
	time.Sleep(50 * time.Millisecond)
	d.Decrement()

	select {
	case <-drainDone:
		require.NoError(t, drainErr)
	case <-time.After(2 * time.Second):
		t.Fatal("drain did not complete in time")
	}
}

func TestDrainer_TimesOut(t *testing.T) {
	d := NewDrainer()

	d.Increment() // Never decremented

	err := d.StartDrain(context.Background(), 100*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "drain timeout")
}

func TestDrainer_ContextCancellation(t *testing.T) {
	d := NewDrainer()

	d.Increment() // Never decremented

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := d.StartDrain(ctx, 5*time.Second)
	require.Error(t, err)
}

func TestDrainer_ConcurrentAccess(t *testing.T) {
	d := NewDrainer()

	var wg sync.WaitGroup
	// Simulate concurrent requests
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.Increment()
			time.Sleep(10 * time.Millisecond)
			d.Decrement()
		}()
	}

	// Start drain while requests are in-flight
	go func() {
		time.Sleep(5 * time.Millisecond)
		_ = d.StartDrain(context.Background(), 5*time.Second)
	}()

	wg.Wait()
	assert.Equal(t, int64(0), d.ActiveCount())
}
