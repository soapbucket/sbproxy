package keys

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/events"
)

// collectingBus records published events for assertions.
type collectingBus struct {
	mu       sync.Mutex
	events   []events.SystemEvent
	handlers map[events.EventType][]events.EventHandler
}

func newCollectingBus() *collectingBus {
	return &collectingBus{
		handlers: make(map[events.EventType][]events.EventHandler),
	}
}

func (b *collectingBus) Publish(event events.SystemEvent) error {
	b.mu.Lock()
	b.events = append(b.events, event)
	handlers := append([]events.EventHandler(nil), b.handlers[event.Type]...)
	b.mu.Unlock()
	for _, h := range handlers {
		_ = h(event)
	}
	return nil
}

func (b *collectingBus) Subscribe(eventType events.EventType, handler events.EventHandler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[eventType] = append(b.handlers[eventType], handler)
}

func (b *collectingBus) Unsubscribe(events.EventType, events.EventHandler) {}
func (b *collectingBus) Close() error                                      { return nil }

func (b *collectingBus) published() []events.SystemEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]events.SystemEvent, len(b.events))
	copy(out, b.events)
	return out
}

func TestRotationSubscriber_RotateWithGrace(t *testing.T) {
	bus := newCollectingBus()
	events.SetBus(bus)
	defer events.SetBus(events.NewInProcessEventBus(100))

	store := NewMemoryStore()
	vk := &VirtualKey{
		ID:          "key-1",
		HashedKey:   "hash-1",
		Status:      "active",
		WorkspaceID: "ws-1",
	}
	if err := store.Create(context.Background(), vk); err != nil {
		t.Fatal(err)
	}

	sub := NewRotationSubscriber(store, 2*time.Hour)
	sub.Subscribe()

	err := sub.handleRotateNow(events.SystemEvent{
		Type: EventKeyRotateNow,
		Data: map[string]interface{}{
			"key_id":       "key-1",
			"grace_period": 30 * time.Minute,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify key status changed.
	updated, err := store.GetByID(context.Background(), "key-1")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != "rotating" {
		t.Errorf("expected status 'rotating', got %q", updated.Status)
	}

	// Verify confirmation event was published.
	published := bus.published()
	found := false
	for _, e := range published {
		if e.Type == EventKeyRotated {
			found = true
			if e.Data["key_id"] != "key-1" {
				t.Errorf("expected key_id=key-1, got %v", e.Data["key_id"])
			}
		}
	}
	if !found {
		t.Error("expected ai.key.rotated event to be published")
	}
}

func TestRotationSubscriber_RevokeImmediate(t *testing.T) {
	bus := newCollectingBus()
	events.SetBus(bus)
	defer events.SetBus(events.NewInProcessEventBus(100))

	store := NewMemoryStore()
	vk := &VirtualKey{
		ID:          "key-2",
		HashedKey:   "hash-2",
		Status:      "active",
		WorkspaceID: "ws-1",
	}
	if err := store.Create(context.Background(), vk); err != nil {
		t.Fatal(err)
	}

	sub := NewRotationSubscriber(store, time.Hour)
	sub.Subscribe()

	err := sub.handleRevoke(events.SystemEvent{
		Type: EventKeyRevoke,
		Data: map[string]interface{}{
			"key_id": "key-2",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify key is revoked.
	updated, err := store.GetByID(context.Background(), "key-2")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != "revoked" {
		t.Errorf("expected status 'revoked', got %q", updated.Status)
	}

	// Verify confirmation event.
	published := bus.published()
	found := false
	for _, e := range published {
		if e.Type == EventKeyRevoked {
			found = true
		}
	}
	if !found {
		t.Error("expected ai.key.revoked event to be published")
	}
}

func TestRotationSubscriber_UnknownKeyError(t *testing.T) {
	bus := newCollectingBus()
	events.SetBus(bus)
	defer events.SetBus(events.NewInProcessEventBus(100))

	store := NewMemoryStore()
	sub := NewRotationSubscriber(store, time.Hour)

	err := sub.handleRotateNow(events.SystemEvent{
		Type: EventKeyRotateNow,
		Data: map[string]interface{}{
			"key_id": "nonexistent",
		},
	})
	if err == nil {
		t.Fatal("expected error for unknown key")
	}

	err = sub.handleRevoke(events.SystemEvent{
		Type: EventKeyRevoke,
		Data: map[string]interface{}{
			"key_id": "nonexistent",
		},
	})
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
}
