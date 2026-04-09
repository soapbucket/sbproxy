package callbacks

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockCallback is a test double that records payloads.
type mockCallback struct {
	name     string
	payloads []*CallbackPayload
	mu       sync.Mutex
	sendErr  error
}

func (m *mockCallback) Name() string { return m.name }

func (m *mockCallback) Send(_ context.Context, payload *CallbackPayload) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.mu.Lock()
	m.payloads = append(m.payloads, payload)
	m.mu.Unlock()
	return nil
}

func (m *mockCallback) Health() error { return nil }

func (m *mockCallback) received() []*CallbackPayload {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]*CallbackPayload, len(m.payloads))
	copy(cp, m.payloads)
	return cp
}

func (m *mockCallback) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.payloads)
}

func TestCallbackManager_AsyncExecution(t *testing.T) {
	mock := &mockCallback{name: "test"}
	mgr := NewCallbackManager(100)
	mgr.Register(mock, &CallbackConfig{Enabled: true, PrivacyMode: "full"})
	mgr.Start()

	payload := &CallbackPayload{
		RequestID:   "req-async-1",
		WorkspaceID: "ws-1",
		Model:       "gpt-4o",
		Provider:    "openai",
		Timestamp:   time.Now(),
		StatusCode:  200,
	}

	mgr.Emit(payload)

	// Allow worker to process.
	time.Sleep(200 * time.Millisecond)
	mgr.Stop()

	if got := mock.count(); got != 1 {
		t.Fatalf("expected 1 payload, got %d", got)
	}
	if mock.received()[0].RequestID != "req-async-1" {
		t.Errorf("request_id = %q, want %q", mock.received()[0].RequestID, "req-async-1")
	}
}

func TestCallbackManager_QueueFullDrops(t *testing.T) {
	mock := &mockCallback{name: "slow"}
	mgr := NewCallbackManager(2) // tiny queue
	mgr.Register(mock, &CallbackConfig{Enabled: true, PrivacyMode: "full"})
	// Do NOT start the worker so the queue fills up.

	for i := 0; i < 10; i++ {
		mgr.Emit(&CallbackPayload{
			RequestID: "req-drop",
			Timestamp: time.Now(),
		})
	}

	// Only 2 should be in the queue; the rest dropped.
	if len(mgr.queue) != 2 {
		t.Errorf("queue length = %d, want 2", len(mgr.queue))
	}
}

func TestCallbackManager_BatchFlushing(t *testing.T) {
	mock := &mockCallback{name: "batch"}
	mgr := NewCallbackManager(100)
	mgr.batchSize = 5
	mgr.flushInterval = 10 * time.Second // long interval so only batch triggers flush
	mgr.Register(mock, &CallbackConfig{Enabled: true, PrivacyMode: "full"})
	mgr.Start()

	for i := 0; i < 5; i++ {
		mgr.Emit(&CallbackPayload{
			RequestID: "req-batch",
			Timestamp: time.Now(),
		})
	}

	// Wait for the batch to flush.
	time.Sleep(200 * time.Millisecond)
	mgr.Stop()

	if got := mock.count(); got != 5 {
		t.Fatalf("expected 5 payloads from batch flush, got %d", got)
	}
}

func TestCallbackManager_TimerFlushing(t *testing.T) {
	mock := &mockCallback{name: "timer"}
	mgr := NewCallbackManager(100)
	mgr.batchSize = 1000                     // large batch so timer triggers first
	mgr.flushInterval = 50 * time.Millisecond // short interval
	mgr.Register(mock, &CallbackConfig{Enabled: true, PrivacyMode: "full"})
	mgr.Start()

	mgr.Emit(&CallbackPayload{
		RequestID: "req-timer",
		Timestamp: time.Now(),
	})

	time.Sleep(200 * time.Millisecond)
	mgr.Stop()

	if got := mock.count(); got != 1 {
		t.Fatalf("expected 1 payload from timer flush, got %d", got)
	}
}

func TestCallbackManager_GracefulShutdown(t *testing.T) {
	mock := &mockCallback{name: "shutdown"}
	mgr := NewCallbackManager(100)
	mgr.batchSize = 1000
	mgr.flushInterval = 10 * time.Minute // very long, won't trigger
	mgr.Register(mock, &CallbackConfig{Enabled: true, PrivacyMode: "full"})
	mgr.Start()

	for i := 0; i < 3; i++ {
		mgr.Emit(&CallbackPayload{
			RequestID: "req-shutdown",
			Timestamp: time.Now(),
		})
	}

	// Stop should drain remaining.
	mgr.Stop()

	if got := mock.count(); got != 3 {
		t.Fatalf("expected 3 payloads after graceful shutdown, got %d", got)
	}
}

func TestCallbackManager_DisabledCallback(t *testing.T) {
	mock := &mockCallback{name: "disabled"}
	mgr := NewCallbackManager(100)
	mgr.Register(mock, &CallbackConfig{Enabled: false, PrivacyMode: "full"})
	mgr.Start()

	mgr.Emit(&CallbackPayload{RequestID: "req-disabled", Timestamp: time.Now()})

	time.Sleep(200 * time.Millisecond)
	mgr.Stop()

	if got := mock.count(); got != 0 {
		t.Fatalf("disabled callback should receive 0 payloads, got %d", got)
	}
}

func TestCallbackManager_MultipleCallbacks(t *testing.T) {
	mock1 := &mockCallback{name: "cb1"}
	mock2 := &mockCallback{name: "cb2"}
	mgr := NewCallbackManager(100)
	mgr.Register(mock1, &CallbackConfig{Enabled: true, PrivacyMode: "full"})
	mgr.Register(mock2, &CallbackConfig{Enabled: true, PrivacyMode: "full"})
	mgr.Start()

	mgr.Emit(&CallbackPayload{RequestID: "req-multi", Timestamp: time.Now()})

	time.Sleep(200 * time.Millisecond)
	mgr.Stop()

	if mock1.count() != 1 {
		t.Errorf("cb1 got %d payloads, want 1", mock1.count())
	}
	if mock2.count() != 1 {
		t.Errorf("cb2 got %d payloads, want 1", mock2.count())
	}
}

func TestCallbackManager_SendErrorDoesNotBlock(t *testing.T) {
	var calls atomic.Int32
	failing := &mockCallback{name: "fail", sendErr: context.DeadlineExceeded}
	good := &mockCallback{name: "good"}
	mgr := NewCallbackManager(100)
	mgr.Register(failing, &CallbackConfig{Enabled: true, PrivacyMode: "full"})
	mgr.Register(good, &CallbackConfig{Enabled: true, PrivacyMode: "full"})
	mgr.Start()

	mgr.Emit(&CallbackPayload{RequestID: "req-err", Timestamp: time.Now()})

	time.Sleep(200 * time.Millisecond)
	mgr.Stop()

	// The good callback should still receive the payload even though the failing one errored.
	if good.count() != 1 {
		t.Errorf("good callback got %d payloads, want 1", good.count())
	}
	_ = calls // suppress unused warning
}

func TestApplyPrivacy_Full(t *testing.T) {
	payload := &CallbackPayload{
		RequestID: "req-priv",
		Model:     "gpt-4o",
		Messages:  []byte(`[{"role":"user","content":"hello"}]`),
	}

	result := applyPrivacy(payload, "full")
	if result != payload {
		t.Error("full mode should return the same pointer")
	}
	if result.Messages == nil {
		t.Error("full mode should not strip messages")
	}
	if result.Model == "" {
		t.Error("full mode should not strip model")
	}
}

func TestApplyPrivacy_Metadata(t *testing.T) {
	payload := &CallbackPayload{
		RequestID: "req-priv",
		Model:     "gpt-4o",
		Messages:  []byte(`[{"role":"user","content":"hello"}]`),
	}

	result := applyPrivacy(payload, "metadata")
	if result == payload {
		t.Error("metadata mode should return a copy")
	}
	if result.Messages != nil {
		t.Error("metadata mode should strip messages")
	}
	if result.Model != "gpt-4o" {
		t.Error("metadata mode should preserve model")
	}
}

func TestApplyPrivacy_Minimal(t *testing.T) {
	payload := &CallbackPayload{
		RequestID: "req-priv",
		Model:     "gpt-4o",
		Messages:  []byte(`[{"role":"user","content":"hello"}]`),
	}

	result := applyPrivacy(payload, "minimal")
	if result == payload {
		t.Error("minimal mode should return a copy")
	}
	if result.Messages != nil {
		t.Error("minimal mode should strip messages")
	}
	if result.Model != "" {
		t.Error("minimal mode should strip model")
	}
}

func TestApplyPrivacy_EmptyDefaultsToFull(t *testing.T) {
	payload := &CallbackPayload{
		RequestID: "req-priv",
		Model:     "gpt-4o",
		Messages:  []byte(`[{"role":"user","content":"hello"}]`),
	}

	result := applyPrivacy(payload, "")
	if result != payload {
		t.Error("empty mode should default to full (same pointer)")
	}
}
