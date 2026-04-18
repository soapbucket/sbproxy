package logging

import (
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// setupTestAppLogger creates an observed zap logger for testing and sets it as the global application logger.
func setupTestAppLogger(level zapcore.Level) (*observer.ObservedLogs, func()) {
	core, logs := observer.New(level)
	logger := zap.New(core)
	SetZapApplicationLogger(logger)
	return logs, func() { SetZapApplicationLogger(nil) }
}

func TestLogConfigReload_Basic(t *testing.T) {
	logs, cleanup := setupTestAppLogger(zapcore.InfoLevel)
	defer cleanup()

	LogConfigReload(AuditSourceFileWatch, []string{"origins", "policies"}, 2, 1)

	if logs.Len() != 1 {
		t.Fatalf("expected 1 log entry, got %d", logs.Len())
	}

	entry := logs.All()[0]
	if entry.Message != "config reloaded" {
		t.Errorf("message = %q, want %q", entry.Message, "config reloaded")
	}
	if entry.Level != zapcore.InfoLevel {
		t.Errorf("level = %v, want Info", entry.Level)
	}

	fields := entry.ContextMap()
	if fields["audit_event"] != "config_reloaded" {
		t.Errorf("audit_event = %v, want %q", fields["audit_event"], "config_reloaded")
	}
	if fields["source"] != string(AuditSourceFileWatch) {
		t.Errorf("source = %v, want %q", fields["source"], AuditSourceFileWatch)
	}
	if v, ok := fields["origins_added"].(int64); !ok || v != 2 {
		t.Errorf("origins_added = %v (%T), want 2", fields["origins_added"], fields["origins_added"])
	}
	if v, ok := fields["origins_removed"].(int64); !ok || v != 1 {
		t.Errorf("origins_removed = %v (%T), want 1", fields["origins_removed"], fields["origins_removed"])
	}
	if _, ok := fields["timestamp"]; !ok {
		t.Error("expected timestamp field to be present")
	}
}

func TestLogConfigReload_AllSources(t *testing.T) {
	sources := []AuditSource{
		AuditSourceFileWatch,
		AuditSourceAPI,
		AuditSourceMesh,
		AuditSourceStartup,
	}

	for _, src := range sources {
		t.Run(string(src), func(t *testing.T) {
			logs, cleanup := setupTestAppLogger(zapcore.InfoLevel)
			defer cleanup()

			LogConfigReload(src, nil, 0, 0)

			if logs.Len() != 1 {
				t.Fatalf("expected 1 log entry, got %d", logs.Len())
			}

			fields := logs.All()[0].ContextMap()
			if fields["source"] != string(src) {
				t.Errorf("source = %v, want %q", fields["source"], src)
			}
		})
	}
}

func TestLogConfigReload_NilLogger(t *testing.T) {
	// Ensure no panic when the logger is nil.
	SetZapApplicationLogger(nil)
	LogConfigReload(AuditSourceStartup, []string{"origins"}, 1, 0)
}

func TestLogConfigReload_EmptyChangedFields(t *testing.T) {
	logs, cleanup := setupTestAppLogger(zapcore.InfoLevel)
	defer cleanup()

	LogConfigReload(AuditSourceAPI, nil, 0, 0)

	if logs.Len() != 1 {
		t.Fatalf("expected 1 log entry, got %d", logs.Len())
	}

	fields := logs.All()[0].ContextMap()
	if v, ok := fields["origins_added"].(int64); !ok || v != 0 {
		t.Errorf("origins_added = %v, want 0", fields["origins_added"])
	}
}
