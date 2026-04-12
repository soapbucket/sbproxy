package ai

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

// testHook is a configurable hook for testing.
type testHook struct {
	name       string
	async      bool
	onChunk    func(ctx context.Context, chunk *SSEEvent, meta *StreamMeta) error
	onComplete func(ctx context.Context, meta *StreamMeta) error
	callCount  int64
}

func (h *testHook) Name() string  { return h.name }
func (h *testHook) IsAsync() bool { return h.async }

func (h *testHook) OnChunk(ctx context.Context, chunk *SSEEvent, meta *StreamMeta) error {
	atomic.AddInt64(&h.callCount, 1)
	if h.onChunk != nil {
		return h.onChunk(ctx, chunk, meta)
	}
	return nil
}

func (h *testHook) OnComplete(ctx context.Context, meta *StreamMeta) error {
	if h.onComplete != nil {
		return h.onComplete(ctx, meta)
	}
	return nil
}

func TestHookChainProcessChunk(t *testing.T) {
	var order []string

	h1 := &testHook{
		name: "first",
		onChunk: func(_ context.Context, _ *SSEEvent, _ *StreamMeta) error {
			order = append(order, "first")
			return nil
		},
	}
	h2 := &testHook{
		name: "second",
		onChunk: func(_ context.Context, _ *SSEEvent, _ *StreamMeta) error {
			order = append(order, "second")
			return nil
		},
	}

	chain := NewHookChain(h1, h2)
	meta := &StreamMeta{RequestID: "test-1", StartTime: time.Now()}
	chunk := &SSEEvent{Data: `{"id":"1"}`}

	if err := chain.ProcessChunk(context.Background(), chunk, meta); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(order) != 2 || order[0] != "first" || order[1] != "second" {
		t.Fatalf("hooks not called in order, got %v", order)
	}
}

func TestHookChainAsync(t *testing.T) {
	done := make(chan struct{})
	asyncHook := &testHook{
		name:  "async-hook",
		async: true,
		onChunk: func(_ context.Context, _ *SSEEvent, _ *StreamMeta) error {
			// Simulate some work.
			time.Sleep(5 * time.Millisecond)
			return nil
		},
		onComplete: func(_ context.Context, _ *StreamMeta) error {
			close(done)
			return nil
		},
	}

	chain := NewHookChain(asyncHook)
	meta := &StreamMeta{RequestID: "async-test", StartTime: time.Now()}
	chunk := &SSEEvent{Data: "test"}

	// ProcessChunk should return immediately (non-blocking).
	start := time.Now()
	if err := chain.ProcessChunk(context.Background(), chunk, meta); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	elapsed := time.Since(start)
	// Should be significantly less than the async hook's sleep time,
	// but allow some slack for CI.
	if elapsed > 3*time.Millisecond {
		t.Logf("warning: ProcessChunk took %v, expected near-instant", elapsed)
	}

	// Complete should wait for async hooks and then call OnComplete.
	if err := chain.Complete(context.Background(), meta); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	select {
	case <-done:
		// Good, OnComplete was called.
	default:
		t.Fatal("async hook OnComplete was not called")
	}
}

func TestTokenCounterHook(t *testing.T) {
	tests := []struct {
		name       string
		data       string
		wantTotal  int64
		wantInput  int64
		wantOutput int64
		wantChunks int64
	}{
		{
			name:       "chunk with usage",
			data:       `{"id":"1","object":"chat.completion.chunk","model":"gpt-4","choices":[],"usage":{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}}`,
			wantTotal:  30,
			wantInput:  10,
			wantOutput: 20,
			wantChunks: 1,
		},
		{
			name:       "chunk without usage",
			data:       `{"id":"1","object":"chat.completion.chunk","model":"gpt-4","choices":[{"index":0,"delta":{"content":"hello"},"finish_reason":null}]}`,
			wantTotal:  0,
			wantInput:  0,
			wantOutput: 0,
			wantChunks: 1,
		},
		{
			name:       "done marker",
			data:       "[DONE]",
			wantTotal:  0,
			wantInput:  0,
			wantOutput: 0,
			wantChunks: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hook := TokenCounterHook{}
			meta := &StreamMeta{StartTime: time.Now()}
			chunk := &SSEEvent{Data: tt.data}

			if err := hook.OnChunk(context.Background(), chunk, meta); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got := meta.LoadTotalTokens(); got != tt.wantTotal {
				t.Errorf("TotalTokens = %d, want %d", got, tt.wantTotal)
			}
			if got := meta.LoadInputTokens(); got != tt.wantInput {
				t.Errorf("InputTokens = %d, want %d", got, tt.wantInput)
			}
			if got := meta.LoadOutputTokens(); got != tt.wantOutput {
				t.Errorf("OutputTokens = %d, want %d", got, tt.wantOutput)
			}
			if got := meta.LoadChunkCount(); got != tt.wantChunks {
				t.Errorf("ChunkCount = %d, want %d", got, tt.wantChunks)
			}
		})
	}
}

func TestBudgetTrackerHook(t *testing.T) {
	t.Run("nil enforcer is no-op", func(t *testing.T) {
		hook := BudgetTrackerHook{Enforcer: nil, ScopeKey: "test"}
		meta := &StreamMeta{StartTime: time.Now()}
		atomic.StoreInt64(&meta.TotalTokens, 100)

		if err := hook.OnComplete(context.Background(), meta); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("zero tokens is no-op", func(t *testing.T) {
		hook := BudgetTrackerHook{Enforcer: &BudgetEnforcer{}, ScopeKey: "test"}
		meta := &StreamMeta{StartTime: time.Now()}

		if err := hook.OnComplete(context.Background(), meta); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestContentFilterHook(t *testing.T) {
	tests := []struct {
		name      string
		blocklist []string
		data      string
		wantErr   bool
	}{
		{
			name:      "no match",
			blocklist: []string{"blocked"},
			data:      `{"choices":[{"delta":{"content":"hello world"}}]}`,
			wantErr:   false,
		},
		{
			name:      "match found",
			blocklist: []string{"blocked"},
			data:      `{"choices":[{"delta":{"content":"this is blocked content"}}]}`,
			wantErr:   true,
		},
		{
			name:      "case insensitive match",
			blocklist: []string{"BLOCKED"},
			data:      `{"choices":[{"delta":{"content":"this is blocked content"}}]}`,
			wantErr:   true,
		},
		{
			name:      "empty blocklist",
			blocklist: nil,
			data:      `{"choices":[{"delta":{"content":"anything"}}]}`,
			wantErr:   false,
		},
		{
			name:      "done marker skipped",
			blocklist: []string{"done"},
			data:      "[DONE]",
			wantErr:   false,
		},
		{
			name:      "nil chunk",
			blocklist: []string{"test"},
			data:      "",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hook := ContentFilterHook{Blocklist: tt.blocklist}
			meta := &StreamMeta{StartTime: time.Now()}

			var chunk *SSEEvent
			if tt.name == "nil chunk" {
				chunk = nil
			} else {
				chunk = &SSEEvent{Data: tt.data}
			}

			err := hook.OnChunk(context.Background(), chunk, meta)
			if (err != nil) != tt.wantErr {
				t.Errorf("OnChunk() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				var aiErr *AIError
				if !errors.As(err, &aiErr) {
					t.Errorf("expected AIError, got %T", err)
				}
			}
		})
	}
}

func TestLoggerHook(t *testing.T) {
	hook := LoggerHook{Logger: slog.Default()}

	if !hook.IsAsync() {
		t.Fatal("LoggerHook should be async")
	}
	if hook.Name() != "logger" {
		t.Fatalf("expected name 'logger', got %q", hook.Name())
	}

	meta := &StreamMeta{
		RequestID: "log-test",
		Model:     "gpt-4",
		Provider:  "openai",
		StartTime: time.Now(),
	}
	chunk := &SSEEvent{Data: `{"id":"1"}`, Event: "message"}

	// Should not panic or error.
	if err := hook.OnChunk(context.Background(), chunk, meta); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := hook.OnComplete(context.Background(), meta); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHookChainError(t *testing.T) {
	errBlocked := errors.New("blocked")

	h1 := &testHook{
		name: "blocker",
		onChunk: func(_ context.Context, _ *SSEEvent, _ *StreamMeta) error {
			return errBlocked
		},
	}
	h2 := &testHook{
		name: "should-not-run",
		onChunk: func(_ context.Context, _ *SSEEvent, _ *StreamMeta) error {
			t.Fatal("second hook should not have been called")
			return nil
		},
	}

	chain := NewHookChain(h1, h2)
	meta := &StreamMeta{StartTime: time.Now()}
	chunk := &SSEEvent{Data: "test"}

	err := chain.ProcessChunk(context.Background(), chunk, meta)
	if !errors.Is(err, errBlocked) {
		t.Fatalf("expected errBlocked, got %v", err)
	}
}

func TestHookChainEmpty(t *testing.T) {
	chain := NewHookChain()
	meta := &StreamMeta{StartTime: time.Now()}
	chunk := &SSEEvent{Data: "test"}

	if err := chain.ProcessChunk(context.Background(), chunk, meta); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := chain.Complete(context.Background(), meta); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Nil chain should also be safe.
	var nilChain *HookChain
	if err := nilChain.ProcessChunk(context.Background(), chunk, meta); err != nil {
		t.Fatalf("unexpected error from nil chain: %v", err)
	}
	if err := nilChain.Complete(context.Background(), meta); err != nil {
		t.Fatalf("unexpected error from nil chain: %v", err)
	}
}

func TestHookChainNilHooksIgnored(t *testing.T) {
	h := &testHook{name: "valid"}
	chain := NewHookChain(nil, h, nil)

	if len(chain.syncHooks) != 1 {
		t.Fatalf("expected 1 sync hook, got %d", len(chain.syncHooks))
	}
}

func TestTokenCounterHookNilChunk(t *testing.T) {
	hook := TokenCounterHook{}
	meta := &StreamMeta{StartTime: time.Now()}

	if err := hook.OnChunk(context.Background(), nil, meta); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := meta.LoadChunkCount(); got != 0 {
		t.Errorf("ChunkCount = %d, want 0", got)
	}
}

func TestStreamMetaAtomicOperations(t *testing.T) {
	meta := &StreamMeta{}

	meta.AddTotalTokens(100)
	meta.AddInputTokens(40)
	meta.AddOutputTokens(60)
	meta.IncrementChunkCount()
	meta.IncrementChunkCount()

	if got := meta.LoadTotalTokens(); got != 100 {
		t.Errorf("TotalTokens = %d, want 100", got)
	}
	if got := meta.LoadInputTokens(); got != 40 {
		t.Errorf("InputTokens = %d, want 40", got)
	}
	if got := meta.LoadOutputTokens(); got != 60 {
		t.Errorf("OutputTokens = %d, want 60", got)
	}
	if got := meta.LoadChunkCount(); got != 2 {
		t.Errorf("ChunkCount = %d, want 2", got)
	}
}
