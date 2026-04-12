package buffer

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/events"
)

func TestMemoryBuffer_EmitsOverflowEvent(t *testing.T) {
	bus := events.NewInProcessEventBus(8)
	defer bus.Close()

	originalBus := events.GetBus()
	events.SetBus(bus)
	defer events.SetBus(originalBus)

	var overflow atomic.Int32
	events.Subscribe(events.EventBufferOverflow, func(event events.SystemEvent) error {
		overflow.Add(1)
		return nil
	})

	buf := NewMemoryBuffer(1, 4, nil)
	_ = buf.Write(&Entry{Data: []byte("1234")})
	_ = buf.Write(&Entry{Data: []byte("5678")})
	time.Sleep(10 * time.Millisecond)

	if overflow.Load() == 0 {
		t.Fatal("expected buffer overflow event")
	}
}

func TestHybridBuffer_EmitsSpillEvent(t *testing.T) {
	bus := events.NewInProcessEventBus(8)
	defer bus.Close()

	originalBus := events.GetBus()
	events.SetBus(bus)
	defer events.SetBus(originalBus)

	var spilled atomic.Int32
	events.Subscribe(events.EventBufferSpilledToDisk, func(event events.SystemEvent) error {
		spilled.Add(1)
		return nil
	})

	dir := t.TempDir()
	buf, err := NewHybridBuffer(1, 8, dir, 1024, nil)
	if err != nil {
		t.Fatalf("new hybrid buffer: %v", err)
	}
	defer buf.Close()

	_ = buf.Write(&Entry{Data: []byte("12345")})
	_ = buf.Write(&Entry{Data: []byte("67890")})
	time.Sleep(10 * time.Millisecond)

	if spilled.Load() == 0 {
		t.Fatal("expected spill-to-disk event")
	}
}
