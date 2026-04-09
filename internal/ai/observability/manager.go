// Package observability provides webhook-based observability hooks for AI request logging.
package observability

import (
	"context"
	"log/slog"
)

// Manager dispatches AI request logs to registered hooks.
type Manager struct {
	hooks []Hook
}

// NewManager creates a new observability manager with the given hooks.
func NewManager(hooks []Hook) *Manager {
	return &Manager{hooks: hooks}
}

// Log sends a log entry to all hooks asynchronously (fire-and-forget).
func (m *Manager) Log(ctx context.Context, log *AIRequestLog) {
	for _, h := range m.hooks {
		h := h // capture for goroutine
		go func() {
			if err := h.Send(ctx, log); err != nil {
				slog.Error("observability hook send failed", "hook", h.Name(), "error", err)
			}
		}()
	}
}

// Close shuts down all hooks, flushing any buffered data.
func (m *Manager) Close() {
	for _, h := range m.hooks {
		if err := h.Close(); err != nil {
			slog.Error("observability hook close failed", "hook", h.Name(), "error", err)
		}
	}
}

// HookCount returns the number of registered hooks.
func (m *Manager) HookCount() int {
	return len(m.hooks)
}
