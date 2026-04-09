package messenger

import (
	"testing"
	"time"
)

func TestMemoryMessenger_WithDelay(t *testing.T) {
	t.Parallel()
	settings := Settings{
		Driver: DriverMemory,
		Params: map[string]string{
			ParamDelay: "100ms",
		},
	}

	msg, err := NewMessenger(settings)
	if err != nil {
		t.Fatal(err)
	}
	defer msg.Close()

	// Test that the delay is set correctly
	memMsg, ok := msg.(*MemoryMessenger)
	if !ok {
		t.Fatal("Expected MemoryMessenger type")
	}

	expectedDelay := 100 * time.Millisecond
	if memMsg.delay != expectedDelay {
		t.Errorf("Expected delay %v, got %v", expectedDelay, memMsg.delay)
	}
}

func TestMemoryMessenger_InvalidDelay(t *testing.T) {
	t.Parallel()
	settings := Settings{
		Driver: DriverMemory,
		Params: map[string]string{
			ParamDelay: "invalid-duration",
		},
	}

	_, err := NewMessenger(settings)
	if err == nil {
		t.Error("Expected error for invalid delay, got nil")
	}
}

func TestMemoryMessenger_DefaultDelay(t *testing.T) {
	t.Parallel()
	settings := Settings{
		Driver: DriverMemory,
		Params: map[string]string{},
	}

	msg, err := NewMessenger(settings)
	if err != nil {
		t.Fatal(err)
	}
	defer msg.Close()

	memMsg, ok := msg.(*MemoryMessenger)
	if !ok {
		t.Fatal("Expected MemoryMessenger type")
	}

	if memMsg.delay != DefaultMemoryDelay {
		t.Errorf("Expected default delay %v, got %v", DefaultMemoryDelay, memMsg.delay)
	}
}
