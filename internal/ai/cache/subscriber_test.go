package cache

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/events"
)

// mockCacheBackend records calls for testing.
type mockCacheBackend struct {
	mu              sync.Mutex
	flushCalls      []string // workspace IDs
	flushModelCalls []string
	flushNSCalls    []string
	deleteCalls     []string
}

func (m *mockCacheBackend) Flush(_ context.Context, workspaceID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushCalls = append(m.flushCalls, workspaceID)
	return nil
}

func (m *mockCacheBackend) FlushModel(_ context.Context, model string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushModelCalls = append(m.flushModelCalls, model)
	return nil
}

func (m *mockCacheBackend) FlushNamespace(_ context.Context, namespace string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushNSCalls = append(m.flushNSCalls, namespace)
	return nil
}

func (m *mockCacheBackend) DeleteEntry(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteCalls = append(m.deleteCalls, key)
	return nil
}

func TestCacheSubscriber_FlushClears(t *testing.T) {
	// Replace global bus with a fresh one for test isolation.
	bus := events.NewInProcessEventBus(100)
	events.SetBus(bus)
	defer bus.Close()

	backend := &mockCacheBackend{}
	sub := NewCacheSubscriber([]CacheBackend{backend}, nil)
	if err := sub.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sub.Stop()

	// Publish flush event.
	bus.Publish(events.SystemEvent{
		Type:   EventAICacheFlush,
		Source: "test",
		Data:   map[string]interface{}{},
	})

	// Wait for async dispatch.
	waitForCondition(t, func() bool {
		backend.mu.Lock()
		defer backend.mu.Unlock()
		return len(backend.flushCalls) >= 1
	})

	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.flushCalls) != 1 {
		t.Fatalf("expected 1 flush call, got %d", len(backend.flushCalls))
	}
	if backend.flushCalls[0] != "" {
		t.Errorf("expected empty workspace_id for global flush, got %q", backend.flushCalls[0])
	}
}

func TestCacheSubscriber_FlushModelScoped(t *testing.T) {
	bus := events.NewInProcessEventBus(100)
	events.SetBus(bus)
	defer bus.Close()

	backend := &mockCacheBackend{}
	sub := NewCacheSubscriber([]CacheBackend{backend}, nil)
	if err := sub.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sub.Stop()

	bus.Publish(events.SystemEvent{
		Type:   EventAICacheFlushModel,
		Source: "test",
		Data:   map[string]interface{}{"model": "gpt-4o"},
	})

	waitForCondition(t, func() bool {
		backend.mu.Lock()
		defer backend.mu.Unlock()
		return len(backend.flushModelCalls) >= 1
	})

	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.flushModelCalls) != 1 || backend.flushModelCalls[0] != "gpt-4o" {
		t.Fatalf("expected flush_model(gpt-4o), got %v", backend.flushModelCalls)
	}
}

func TestCacheSubscriber_FlushNamespace(t *testing.T) {
	bus := events.NewInProcessEventBus(100)
	events.SetBus(bus)
	defer bus.Close()

	backend := &mockCacheBackend{}
	sub := NewCacheSubscriber([]CacheBackend{backend}, nil)
	if err := sub.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sub.Stop()

	bus.Publish(events.SystemEvent{
		Type:   EventAICacheFlushNamespace,
		Source: "test",
		Data:   map[string]interface{}{"namespace": "ws:team-alpha"},
	})

	waitForCondition(t, func() bool {
		backend.mu.Lock()
		defer backend.mu.Unlock()
		return len(backend.flushNSCalls) >= 1
	})

	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.flushNSCalls) != 1 || backend.flushNSCalls[0] != "ws:team-alpha" {
		t.Fatalf("expected flush_namespace(ws:team-alpha), got %v", backend.flushNSCalls)
	}
}

func TestCacheSubscriber_DeleteEntry(t *testing.T) {
	bus := events.NewInProcessEventBus(100)
	events.SetBus(bus)
	defer bus.Close()

	backend := &mockCacheBackend{}
	sub := NewCacheSubscriber([]CacheBackend{backend}, nil)
	if err := sub.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sub.Stop()

	bus.Publish(events.SystemEvent{
		Type:   EventAICacheDeleteEntry,
		Source: "test",
		Data:   map[string]interface{}{"key": "tiered:abc123"},
	})

	waitForCondition(t, func() bool {
		backend.mu.Lock()
		defer backend.mu.Unlock()
		return len(backend.deleteCalls) >= 1
	})

	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.deleteCalls) != 1 || backend.deleteCalls[0] != "tiered:abc123" {
		t.Fatalf("expected delete_entry(tiered:abc123), got %v", backend.deleteCalls)
	}
}

func TestCacheSubscriber_WorkspaceIsolation(t *testing.T) {
	bus := events.NewInProcessEventBus(100)
	events.SetBus(bus)
	defer bus.Close()

	backend := &mockCacheBackend{}
	sub := NewCacheSubscriber([]CacheBackend{backend}, nil)
	if err := sub.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sub.Stop()

	// Flush with workspace_id in the event data.
	bus.Publish(events.SystemEvent{
		Type:        EventAICacheFlush,
		Source:      "test",
		WorkspaceID: "ws-123",
		Data:        map[string]interface{}{},
	})

	waitForCondition(t, func() bool {
		backend.mu.Lock()
		defer backend.mu.Unlock()
		return len(backend.flushCalls) >= 1
	})

	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.flushCalls) != 1 || backend.flushCalls[0] != "ws-123" {
		t.Fatalf("expected flush(ws-123), got %v", backend.flushCalls)
	}
}

func TestCacheSubscriber_MultipleBackends(t *testing.T) {
	bus := events.NewInProcessEventBus(100)
	events.SetBus(bus)
	defer bus.Close()

	b1 := &mockCacheBackend{}
	b2 := &mockCacheBackend{}
	sub := NewCacheSubscriber([]CacheBackend{b1, b2}, nil)
	if err := sub.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sub.Stop()

	bus.Publish(events.SystemEvent{
		Type:   EventAICacheFlush,
		Source: "test",
		Data:   map[string]interface{}{},
	})

	waitForCondition(t, func() bool {
		b1.mu.Lock()
		n1 := len(b1.flushCalls)
		b1.mu.Unlock()
		b2.mu.Lock()
		n2 := len(b2.flushCalls)
		b2.mu.Unlock()
		return n1 >= 1 && n2 >= 1
	})

	b1.mu.Lock()
	if len(b1.flushCalls) != 1 {
		t.Errorf("backend 1: expected 1 flush, got %d", len(b1.flushCalls))
	}
	b1.mu.Unlock()

	b2.mu.Lock()
	if len(b2.flushCalls) != 1 {
		t.Errorf("backend 2: expected 1 flush, got %d", len(b2.flushCalls))
	}
	b2.mu.Unlock()
}

func TestCacheSubscriber_MissingDataIgnored(t *testing.T) {
	bus := events.NewInProcessEventBus(100)
	events.SetBus(bus)
	defer bus.Close()

	backend := &mockCacheBackend{}
	sub := NewCacheSubscriber([]CacheBackend{backend}, nil)
	if err := sub.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sub.Stop()

	// Publish flush_model without a model field - should be a no-op.
	var dispatched atomic.Int32
	events.Subscribe(EventAICacheFlushModel, func(_ events.SystemEvent) error {
		dispatched.Add(1)
		return nil
	})

	bus.Publish(events.SystemEvent{
		Type:   EventAICacheFlushModel,
		Source: "test",
		Data:   map[string]interface{}{}, // Missing "model"
	})

	waitForCondition(t, func() bool {
		return dispatched.Load() >= 1
	})

	// Give a little extra time for the subscriber handler to run.
	time.Sleep(20 * time.Millisecond)

	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.flushModelCalls) != 0 {
		t.Fatalf("expected 0 flush_model calls for missing data, got %d", len(backend.flushModelCalls))
	}
}

// waitForCondition polls fn until it returns true, with a timeout.
func waitForCondition(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for condition")
}
