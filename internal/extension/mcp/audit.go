package mcp

import (
	"log/slog"
	"time"
)

// AuditLogger logs structured audit entries for every tool call.
type AuditLogger struct {
	logger *slog.Logger
}

// NewAuditLogger creates a new audit logger.
func NewAuditLogger(logger *slog.Logger) *AuditLogger {
	if logger == nil {
		logger = slog.Default()
	}
	return &AuditLogger{logger: logger}
}

// LogToolCall logs a tool call with identity, arguments, result status, and latency.
func (a *AuditLogger) LogToolCall(entry AuditEntry) {
	a.logger.Info("mcp.audit.tool_call",
		"tool", entry.ToolName,
		"user_roles", entry.Roles,
		"key_id", entry.KeyID,
		"is_error", entry.IsError,
		"latency_ms", entry.Latency.Milliseconds(),
		"cached", entry.Cached,
		"upstream", entry.Upstream,
	)
}

// AuditEntry represents a single audit log entry for a tool call.
type AuditEntry struct {
	ToolName  string
	Roles     []string
	KeyID     string
	IsError   bool
	Latency   time.Duration
	Cached    bool
	Upstream  string // Upstream server URL for gateway mode
}
