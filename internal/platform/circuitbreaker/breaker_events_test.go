package circuitbreaker

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/events"
)

func TestCircuitBreaker_EmitsHalfOpenEvent(t *testing.T) {
	bus := events.NewInProcessEventBus(8)
	defer bus.Close()

	originalBus := events.GetBus()
	events.SetBus(bus)
	defer events.SetBus(originalBus)

	var halfOpen atomic.Int32
	events.Subscribe(events.EventCircuitBreakerHalfOpen, func(event events.SystemEvent) error {
		halfOpen.Add(1)
		return nil
	})

	cb := New(Config{
		Name:             "svc",
		FailureThreshold: 1,
		SuccessThreshold: 1,
		Timeout:          time.Millisecond,
	})

	cb.emitStateChangeEvent(StateOpen, StateHalfOpen)
	time.Sleep(10 * time.Millisecond)

	if halfOpen.Load() == 0 {
		t.Fatal("expected half-open event to be emitted")
	}
}
