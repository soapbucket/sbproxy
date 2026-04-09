// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	json "github.com/goccy/go-json"
)

// StreamChunkHook observes SSE chunks as they flow through the streaming pipeline.
// Hooks run inline (sync) or in background goroutines (async) depending on IsAsync.
type StreamChunkHook interface {
	// Name returns a human-readable identifier for this hook.
	Name() string
	// OnChunk is called for each SSE chunk. Returns an error to terminate the stream.
	OnChunk(ctx context.Context, chunk *SSEEvent, meta *StreamMeta) error
	// OnComplete is called when the stream ends normally or due to error.
	OnComplete(ctx context.Context, meta *StreamMeta) error
	// IsAsync returns true if this hook should run asynchronously (non-blocking).
	IsAsync() bool
}

// StreamMeta holds metadata about an in-progress stream, updated by hooks.
type StreamMeta struct {
	Model       string
	Provider    string
	StartTime   time.Time
	TotalTokens int64
	InputTokens int64
	OutputTokens int64
	ChunkCount  int64
	RequestID   string
}

// AddTotalTokens atomically adds to TotalTokens.
func (m *StreamMeta) AddTotalTokens(n int64) {
	atomic.AddInt64(&m.TotalTokens, n)
}

// AddInputTokens atomically adds to InputTokens.
func (m *StreamMeta) AddInputTokens(n int64) {
	atomic.AddInt64(&m.InputTokens, n)
}

// AddOutputTokens atomically adds to OutputTokens.
func (m *StreamMeta) AddOutputTokens(n int64) {
	atomic.AddInt64(&m.OutputTokens, n)
}

// IncrementChunkCount atomically increments ChunkCount and returns the new value.
func (m *StreamMeta) IncrementChunkCount() int64 {
	return atomic.AddInt64(&m.ChunkCount, 1)
}

// LoadTotalTokens atomically loads TotalTokens.
func (m *StreamMeta) LoadTotalTokens() int64 {
	return atomic.LoadInt64(&m.TotalTokens)
}

// LoadInputTokens atomically loads InputTokens.
func (m *StreamMeta) LoadInputTokens() int64 {
	return atomic.LoadInt64(&m.InputTokens)
}

// LoadOutputTokens atomically loads OutputTokens.
func (m *StreamMeta) LoadOutputTokens() int64 {
	return atomic.LoadInt64(&m.OutputTokens)
}

// LoadChunkCount atomically loads ChunkCount.
func (m *StreamMeta) LoadChunkCount() int64 {
	return atomic.LoadInt64(&m.ChunkCount)
}

// HookChain manages an ordered list of StreamChunkHooks.
// Sync hooks run inline in order; async hooks run in background goroutines.
type HookChain struct {
	syncHooks  []StreamChunkHook
	asyncHooks []StreamChunkHook
	wg         sync.WaitGroup
}

// NewHookChain creates a HookChain from the given hooks, partitioned by sync/async.
func NewHookChain(hooks ...StreamChunkHook) *HookChain {
	hc := &HookChain{}
	for _, h := range hooks {
		if h == nil {
			continue
		}
		if h.IsAsync() {
			hc.asyncHooks = append(hc.asyncHooks, h)
		} else {
			hc.syncHooks = append(hc.syncHooks, h)
		}
	}
	return hc
}

// ProcessChunk runs all hooks for a single SSE chunk.
// Sync hooks run in order; if any returns an error, processing stops and the error is returned.
// Async hooks run concurrently and do not block the caller.
func (hc *HookChain) ProcessChunk(ctx context.Context, chunk *SSEEvent, meta *StreamMeta) error {
	if hc == nil {
		return nil
	}

	// Run sync hooks inline, in order.
	for _, h := range hc.syncHooks {
		if err := h.OnChunk(ctx, chunk, meta); err != nil {
			return err
		}
	}

	// Fire async hooks in background goroutines.
	for _, h := range hc.asyncHooks {
		hc.wg.Add(1)
		go func(hook StreamChunkHook) {
			defer hc.wg.Done()
			_ = hook.OnChunk(ctx, chunk, meta)
		}(h)
	}

	return nil
}

// Complete signals all hooks that the stream has ended and waits for async hooks to drain.
func (hc *HookChain) Complete(ctx context.Context, meta *StreamMeta) error {
	if hc == nil {
		return nil
	}

	// Wait for any in-flight async chunk hooks to finish first.
	hc.wg.Wait()

	// Run sync completion hooks.
	var firstErr error
	for _, h := range hc.syncHooks {
		if err := h.OnComplete(ctx, meta); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// Run async completion hooks.
	for _, h := range hc.asyncHooks {
		hc.wg.Add(1)
		go func(hook StreamChunkHook) {
			defer hc.wg.Done()
			_ = hook.OnComplete(ctx, meta)
		}(h)
	}
	hc.wg.Wait()

	return firstErr
}

// --- Built-in Hooks ---

// TokenCounterHook extracts token usage from stream chunks and updates StreamMeta.
type TokenCounterHook struct{}

// Name returns the hook name.
func (TokenCounterHook) Name() string { return "token_counter" }

// IsAsync returns false; token counting must be synchronous so downstream hooks see updated counts.
func (TokenCounterHook) IsAsync() bool { return false }

// OnChunk parses usage data from the SSE chunk and updates StreamMeta counters.
func (TokenCounterHook) OnChunk(_ context.Context, chunk *SSEEvent, meta *StreamMeta) error {
	if chunk == nil || IsDone(chunk.Data) {
		return nil
	}
	meta.IncrementChunkCount()

	var sc StreamChunk
	if err := json.Unmarshal([]byte(chunk.Data), &sc); err != nil {
		// Not a JSON chunk (e.g., Anthropic event type), skip silently.
		return nil
	}
	if sc.Usage != nil {
		meta.AddInputTokens(int64(sc.Usage.PromptTokens))
		meta.AddOutputTokens(int64(sc.Usage.CompletionTokens))
		meta.AddTotalTokens(int64(sc.Usage.TotalTokens))
	}
	return nil
}

// OnComplete is a no-op for the token counter.
func (TokenCounterHook) OnComplete(_ context.Context, _ *StreamMeta) error { return nil }

// BudgetTrackerHook tracks token usage against a BudgetEnforcer during streaming.
type BudgetTrackerHook struct {
	Enforcer *BudgetEnforcer
	ScopeKey string
}

// Name returns the hook name.
func (BudgetTrackerHook) Name() string { return "budget_tracker" }

// IsAsync returns false; budget checks must be synchronous to block the stream if exceeded.
func (BudgetTrackerHook) IsAsync() bool { return false }

// OnChunk is a no-op per-chunk; budget is checked on completion when final usage is known.
func (h BudgetTrackerHook) OnChunk(_ context.Context, _ *SSEEvent, _ *StreamMeta) error {
	return nil
}

// OnComplete records the final token usage with the budget enforcer.
func (h BudgetTrackerHook) OnComplete(ctx context.Context, meta *StreamMeta) error {
	if h.Enforcer == nil {
		return nil
	}
	tokens := meta.LoadTotalTokens()
	if tokens <= 0 {
		return nil
	}
	return h.Enforcer.Record(ctx, h.ScopeKey, tokens, 0)
}

// ContentFilterHook checks chunk content against a keyword blocklist.
// If a blocked keyword is found, it returns an error to terminate the stream.
type ContentFilterHook struct {
	Blocklist []string
}

// Name returns the hook name.
func (ContentFilterHook) Name() string { return "content_filter" }

// IsAsync returns false; content filtering must be synchronous to terminate the stream immediately.
func (ContentFilterHook) IsAsync() bool { return false }

// OnChunk checks the chunk data against the blocklist. Returns an error if blocked content is found.
func (h ContentFilterHook) OnChunk(_ context.Context, chunk *SSEEvent, _ *StreamMeta) error {
	if chunk == nil || IsDone(chunk.Data) || len(h.Blocklist) == 0 {
		return nil
	}
	lower := strings.ToLower(chunk.Data)
	for _, keyword := range h.Blocklist {
		if strings.Contains(lower, strings.ToLower(keyword)) {
			return &AIError{
				Message: "content blocked by filter",
				Type:    "content_filter",
				Code:    "content_blocked",
			}
		}
	}
	return nil
}

// OnComplete is a no-op for the content filter.
func (ContentFilterHook) OnComplete(_ context.Context, _ *StreamMeta) error { return nil }

// LoggerHook logs chunk metadata to slog asynchronously.
type LoggerHook struct {
	Logger *slog.Logger
}

// Name returns the hook name.
func (LoggerHook) Name() string { return "logger" }

// IsAsync returns true; logging should not block the stream.
func (LoggerHook) IsAsync() bool { return true }

// OnChunk logs basic chunk info.
func (h LoggerHook) OnChunk(_ context.Context, chunk *SSEEvent, meta *StreamMeta) error {
	logger := h.logger()
	if chunk == nil {
		return nil
	}
	logger.Debug("stream chunk",
		"request_id", meta.RequestID,
		"event", chunk.Event,
		"data_len", len(chunk.Data),
		"chunk_count", meta.LoadChunkCount(),
	)
	return nil
}

// OnComplete logs stream completion summary.
func (h LoggerHook) OnComplete(_ context.Context, meta *StreamMeta) error {
	logger := h.logger()
	logger.Info("stream complete",
		"request_id", meta.RequestID,
		"model", meta.Model,
		"provider", meta.Provider,
		"total_tokens", meta.LoadTotalTokens(),
		"input_tokens", meta.LoadInputTokens(),
		"output_tokens", meta.LoadOutputTokens(),
		"chunks", meta.LoadChunkCount(),
		"duration_ms", time.Since(meta.StartTime).Milliseconds(),
	)
	return nil
}

func (h LoggerHook) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

