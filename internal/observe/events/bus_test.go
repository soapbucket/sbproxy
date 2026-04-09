package events

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestInProcessEventBus_DoesNotBlockOnSlowHandler(t *testing.T) {
	bus := NewInProcessEventBus(10)
	defer bus.Close()

	var fastCalls atomic.Int32
	bus.Subscribe(EventClickHouseFlushSuccess, func(event SystemEvent) error {
		time.Sleep(80 * time.Millisecond)
		return nil
	})
	bus.Subscribe(EventClickHouseFlushSuccess, func(event SystemEvent) error {
		fastCalls.Add(1)
		return nil
	})

	start := time.Now()
	if err := bus.Publish(SystemEvent{Type: EventClickHouseFlushSuccess}); err != nil {
		t.Fatalf("publish failed: %v", err)
	}

	// Give async handlers time to execute.
	time.Sleep(30 * time.Millisecond)
	if fastCalls.Load() == 0 {
		t.Fatalf("expected fast handler to run independently")
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("publish path took too long: %v", elapsed)
	}
}
