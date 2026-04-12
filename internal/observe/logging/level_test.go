package logging

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"
)

// mockHandler is a simple handler for testing
type mockHandler struct {
	handled bool
	level   slog.Level
}

func (m *mockHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= m.level
}

func (m *mockHandler) Handle(ctx context.Context, record slog.Record) error {
	m.handled = true
	return nil
}

func (m *mockHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return m
}

func (m *mockHandler) WithGroup(name string) slog.Handler {
	return m
}

func TestNewLevelHandler(t *testing.T) {
	mock := &mockHandler{level: slog.LevelInfo}
	handler := NewLevelHandler(slog.LevelInfo, mock)

	if handler == nil {
		t.Fatal("NewLevelHandler returned nil")
	}

	if handler.GetLevel() != slog.LevelInfo {
		t.Errorf("Expected level INFO, got %v", handler.GetLevel())
	}
}

func TestLevelHandler_SetLevel(t *testing.T) {
	mock := &mockHandler{level: slog.LevelInfo}
	handler := NewLevelHandler(slog.LevelInfo, mock)

	// Test setting different levels
	levels := []slog.Level{
		slog.LevelDebug,
		slog.LevelInfo,
		slog.LevelWarn,
		slog.LevelError,
	}

	for _, level := range levels {
		handler.SetLevel(level)
		if handler.GetLevel() != level {
			t.Errorf("Expected level %v, got %v", level, handler.GetLevel())
		}
	}
}

func TestLevelHandler_Enabled(t *testing.T) {
	mock := &mockHandler{level: slog.LevelInfo}
	handler := NewLevelHandler(slog.LevelInfo, mock)
	ctx := context.Background()

	// Test with INFO level
	tests := []struct {
		name     string
		level    slog.Level
		expected bool
	}{
		{"DEBUG below INFO", slog.LevelDebug, false},
		{"INFO equals INFO", slog.LevelInfo, true},
		{"WARN above INFO", slog.LevelWarn, true},
		{"ERROR above INFO", slog.LevelError, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.Enabled(ctx, tt.level)
			if result != tt.expected {
				t.Errorf("Enabled(%v) = %v, expected %v", tt.level, result, tt.expected)
			}
		})
	}

	// Change level to DEBUG and test again
	handler.SetLevel(slog.LevelDebug)
	if !handler.Enabled(ctx, slog.LevelDebug) {
		t.Error("Expected DEBUG to be enabled when level is DEBUG")
	}
}

func TestLevelHandler_Handle(t *testing.T) {
	mock := &mockHandler{level: slog.LevelInfo}
	handler := NewLevelHandler(slog.LevelInfo, mock)
	ctx := context.Background()

	record := slog.NewRecord(time.Now(), slog.LevelInfo, "test", 0)
	if err := handler.Handle(ctx, record); err != nil {
		t.Errorf("Handle() returned error: %v", err)
	}

	if !mock.handled {
		t.Error("Expected mock handler to be called")
	}
}

func TestLevelHandler_WithAttrs(t *testing.T) {
	mock := &mockHandler{level: slog.LevelInfo}
	handler := NewLevelHandler(slog.LevelInfo, mock)

	newHandler := handler.WithAttrs([]slog.Attr{slog.String("key", "value")})
	if newHandler == nil {
		t.Fatal("WithAttrs returned nil")
	}

	// Verify it's still a LevelHandler
	levelHandler, ok := newHandler.(*LevelHandler)
	if !ok {
		t.Fatal("WithAttrs did not return a LevelHandler")
	}

	// Verify level is preserved
	if levelHandler.GetLevel() != slog.LevelInfo {
		t.Errorf("Expected level INFO, got %v", levelHandler.GetLevel())
	}
}

func TestLevelHandler_WithGroup(t *testing.T) {
	mock := &mockHandler{level: slog.LevelInfo}
	handler := NewLevelHandler(slog.LevelInfo, mock)

	newHandler := handler.WithGroup("testgroup")
	if newHandler == nil {
		t.Fatal("WithGroup returned nil")
	}

	// Verify it's still a LevelHandler
	levelHandler, ok := newHandler.(*LevelHandler)
	if !ok {
		t.Fatal("WithGroup did not return a LevelHandler")
	}

	// Verify level is preserved
	if levelHandler.GetLevel() != slog.LevelInfo {
		t.Errorf("Expected level INFO, got %v", levelHandler.GetLevel())
	}
}

func TestSetGlobalLogLevel(t *testing.T) {
	// Create handlers for all three logger types
	appHandler := NewLevelHandler(slog.LevelInfo, &mockHandler{level: slog.LevelInfo})
	reqHandler := NewLevelHandler(slog.LevelInfo, &mockHandler{level: slog.LevelInfo})
	secHandler := NewLevelHandler(slog.LevelInfo, &mockHandler{level: slog.LevelInfo})

	SetApplicationLevelHandler(appHandler)
	SetRequestLevelHandler(reqHandler)
	SetSecurityLevelHandler(secHandler)

	// Test setting global level
	SetGlobalLogLevel(slog.LevelDebug)

	// Verify all handlers were updated
	if appHandler.GetLevel() != slog.LevelDebug {
		t.Errorf("Application handler level = %v, expected DEBUG", appHandler.GetLevel())
	}
	if reqHandler.GetLevel() != slog.LevelDebug {
		t.Errorf("Request handler level = %v, expected DEBUG", reqHandler.GetLevel())
	}
	if secHandler.GetLevel() != slog.LevelDebug {
		t.Errorf("Security handler level = %v, expected DEBUG", secHandler.GetLevel())
	}

	// Test setting back to INFO
	SetGlobalLogLevel(slog.LevelInfo)
	if GetGlobalLogLevel() != slog.LevelInfo {
		t.Errorf("GetGlobalLogLevel() = %v, expected INFO", GetGlobalLogLevel())
	}
}

func TestGetGlobalLogLevel(t *testing.T) {
	// Test with no handler set (should return INFO default)
	SetApplicationLevelHandler(nil)
	level := GetGlobalLogLevel()
	if level != slog.LevelInfo {
		t.Errorf("Expected default INFO level, got %v", level)
	}

	// Test with handler set
	handler := NewLevelHandler(slog.LevelWarn, &mockHandler{level: slog.LevelWarn})
	SetApplicationLevelHandler(handler)
	level = GetGlobalLogLevel()
	if level != slog.LevelWarn {
		t.Errorf("Expected WARN level, got %v", level)
	}
}

func TestLevelHandler_ConcurrentAccess(t *testing.T) {
	mock := &mockHandler{level: slog.LevelInfo}
	handler := NewLevelHandler(slog.LevelInfo, mock)

	// Test concurrent level changes
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				handler.SetLevel(slog.LevelDebug)
				handler.GetLevel()
				handler.SetLevel(slog.LevelInfo)
				handler.GetLevel()
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Final level should be one of the set levels
	level := handler.GetLevel()
	if level != slog.LevelDebug && level != slog.LevelInfo {
		t.Errorf("Expected level to be DEBUG or INFO, got %v", level)
	}
}

func TestLevelHandler_IntegrationWithJSONHandler(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	levelHandler := NewLevelHandler(slog.LevelInfo, baseHandler)
	logger := slog.New(levelHandler)

	// Log at INFO level (should be enabled)
	logger.Info("test message")
	if buf.Len() == 0 {
		t.Error("Expected log output at INFO level")
	}

	// Change level to WARN
	buf.Reset()
	levelHandler.SetLevel(slog.LevelWarn)

	// Log at INFO level (should be disabled)
	logger.Info("test message")
	if buf.Len() != 0 {
		t.Error("Expected no log output at INFO level when level is WARN")
	}

	// Log at WARN level (should be enabled)
	logger.Warn("test message")
	if buf.Len() == 0 {
		t.Error("Expected log output at WARN level")
	}
}

func TestLevelHandler_IntegrationWithLevelChange(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	levelHandler := NewLevelHandler(slog.LevelInfo, baseHandler)
	logger := slog.New(levelHandler)

	// Log at INFO level (should be enabled)
	logger.Info("test message")
	if buf.Len() == 0 {
		t.Error("Expected log output at INFO level")
	}

	// Change level to ERROR
	buf.Reset()
	levelHandler.SetLevel(slog.LevelError)

	// Log at INFO level (should be disabled)
	logger.Info("test message")
	if buf.Len() != 0 {
		t.Error("Expected no log output at INFO level when level is ERROR")
	}

	// Log at ERROR level (should be enabled)
	logger.Error("test message")
	if buf.Len() == 0 {
		t.Error("Expected log output at ERROR level")
	}
}
