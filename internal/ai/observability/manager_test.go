package observability

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockHook is a test hook that records sent logs.
type mockHook struct {
	name    string
	logs    []*AIRequestLog
	mu      sync.Mutex
	closed  atomic.Bool
	sendErr error
}

func (m *mockHook) Name() string { return m.name }

func (m *mockHook) Send(_ context.Context, log *AIRequestLog) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.mu.Lock()
	m.logs = append(m.logs, log)
	m.mu.Unlock()
	return nil
}

func (m *mockHook) Close() error {
	m.closed.Store(true)
	return nil
}

func (m *mockHook) Logs() []*AIRequestLog {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]*AIRequestLog, len(m.logs))
	copy(cp, m.logs)
	return cp
}

func TestObservabilityManager_DispatchesToMultipleHooks(t *testing.T) {
	hook1 := &mockHook{name: "hook1"}
	hook2 := &mockHook{name: "hook2"}

	mgr := NewManager([]Hook{hook1, hook2})

	log := &AIRequestLog{
		RequestID:    "req-dispatch",
		Timestamp:    time.Now(),
		Provider:     "anthropic",
		Model:        "claude-sonnet-4-20250514",
		InputTokens:  200,
		OutputTokens: 100,
		StatusCode:   200,
	}

	mgr.Log(context.Background(), log)

	// Wait for async dispatch
	time.Sleep(100 * time.Millisecond)

	logs1 := hook1.Logs()
	logs2 := hook2.Logs()

	if len(logs1) != 1 {
		t.Errorf("hook1 received %d logs, want 1", len(logs1))
	}
	if len(logs2) != 1 {
		t.Errorf("hook2 received %d logs, want 1", len(logs2))
	}

	if len(logs1) > 0 && logs1[0].RequestID != "req-dispatch" {
		t.Errorf("hook1 log request_id = %q, want %q", logs1[0].RequestID, "req-dispatch")
	}
}

func TestObservabilityManager_CloseAllHooks(t *testing.T) {
	hook1 := &mockHook{name: "hook1"}
	hook2 := &mockHook{name: "hook2"}

	mgr := NewManager([]Hook{hook1, hook2})
	mgr.Close()

	if !hook1.closed.Load() {
		t.Error("hook1 was not closed")
	}
	if !hook2.closed.Load() {
		t.Error("hook2 was not closed")
	}
}

func TestObservabilityManager_HookCount(t *testing.T) {
	mgr := NewManager([]Hook{&mockHook{name: "a"}, &mockHook{name: "b"}, &mockHook{name: "c"}})
	if mgr.HookCount() != 3 {
		t.Errorf("HookCount() = %d, want 3", mgr.HookCount())
	}
}

func TestObservabilityManager_EmptyHooks(t *testing.T) {
	mgr := NewManager(nil)
	// Should not panic
	mgr.Log(context.Background(), &AIRequestLog{RequestID: "req-empty"})
	mgr.Close()
}

func TestObservabilityManager_SendErrorDoesNotPanic(t *testing.T) {
	hook := &mockHook{name: "failing", sendErr: context.DeadlineExceeded}
	mgr := NewManager([]Hook{hook})

	// Should not panic even when Send returns error
	mgr.Log(context.Background(), &AIRequestLog{RequestID: "req-fail"})
	time.Sleep(50 * time.Millisecond)

	mgr.Close()
}
