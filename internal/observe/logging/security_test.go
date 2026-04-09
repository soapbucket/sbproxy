package logging

import (
	"context"
	"encoding/json"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// setupTestSecurityLogger creates an observed zap logger for testing and sets it as the global security logger.
func setupTestSecurityLogger(level zapcore.Level) (*observer.ObservedLogs, func()) {
	core, logs := observer.New(level)
	logger := zap.New(core)
	SetZapSecurityLogger(logger)
	return logs, func() { SetZapSecurityLogger(nil) }
}

func TestLogSecurityEvent(t *testing.T) {
	logs, cleanup := setupTestSecurityLogger(zapcore.InfoLevel)
	defer cleanup()

	ctx := reqctx.SetRequestID(context.Background(), "test-request-123")

	LogSecurityEvent(
		ctx,
		SecurityEventAuthFailure,
		SeverityHigh,
		"authenticate",
		"failure",
		zap.String("test_field", "test_value"),
	)

	if logs.Len() != 1 {
		t.Fatalf("Expected 1 log entry, got %d", logs.Len())
	}

	entry := logs.All()[0]
	if entry.Message != "security event" {
		t.Errorf("Expected msg='security event', got %v", entry.Message)
	}

	// SeverityHigh → Warn
	if entry.Level != zapcore.WarnLevel {
		t.Errorf("Expected level=Warn for SeverityHigh, got %v", entry.Level)
	}

	fields := fieldMap(entry.ContextMap())
	if fields["event_type"] != SecurityEventAuthFailure {
		t.Errorf("Expected event_type=%s, got %v", SecurityEventAuthFailure, fields["event_type"])
	}
	if fields["severity"] != SeverityHigh {
		t.Errorf("Expected severity=%s, got %v", SeverityHigh, fields["severity"])
	}
	if fields["action"] != "authenticate" {
		t.Errorf("Expected action='authenticate', got %v", fields["action"])
	}
	if fields["result"] != "failure" {
		t.Errorf("Expected result='failure', got %v", fields["result"])
	}
	if fields["request_id"] != "test-request-123" {
		t.Errorf("Expected request_id='test-request-123', got %v", fields["request_id"])
	}
	if fields["test_field"] != "test_value" {
		t.Errorf("Expected test_field='test_value', got %v", fields["test_field"])
	}
}

func TestLogAuthenticationAttempt_Success(t *testing.T) {
	logs, cleanup := setupTestSecurityLogger(zapcore.InfoLevel)
	defer cleanup()

	ctx := reqctx.SetRequestID(context.Background(), "test-request-456")
	LogAuthenticationAttempt(ctx, true, "basic", "user@example.com", "192.168.1.100", "")

	if logs.Len() != 1 {
		t.Fatalf("Expected 1 log entry, got %d", logs.Len())
	}

	fields := fieldMap(logs.All()[0].ContextMap())
	if fields["event_type"] != SecurityEventAuthSuccess {
		t.Errorf("Expected event_type=%s, got %v", SecurityEventAuthSuccess, fields["event_type"])
	}
	if fields["result"] != "success" {
		t.Errorf("Expected result='success', got %v", fields["result"])
	}
	if fields["auth_type"] != "basic" {
		t.Errorf("Expected auth_type='basic', got %v", fields["auth_type"])
	}
	if fields["username"] != "user@example.com" {
		t.Errorf("Expected username='user@example.com', got %v", fields["username"])
	}
	if fields["ip"] != "192.168.1.100" {
		t.Errorf("Expected ip='192.168.1.100', got %v", fields["ip"])
	}
}

func TestLogAuthenticationAttempt_Failure(t *testing.T) {
	logs, cleanup := setupTestSecurityLogger(zapcore.InfoLevel)
	defer cleanup()

	ctx := reqctx.SetRequestID(context.Background(), "test-request-789")
	LogAuthenticationAttempt(ctx, false, "jwt", "attacker@evil.com", "10.0.0.1", "invalid credentials")

	if logs.Len() != 1 {
		t.Fatalf("Expected 1 log entry, got %d", logs.Len())
	}

	entry := logs.All()[0]
	// SeverityHigh → Warn
	if entry.Level != zapcore.WarnLevel {
		t.Errorf("Expected level=Warn for auth failure, got %v", entry.Level)
	}

	fields := fieldMap(entry.ContextMap())
	if fields["event_type"] != SecurityEventAuthFailure {
		t.Errorf("Expected event_type=%s, got %v", SecurityEventAuthFailure, fields["event_type"])
	}
	if fields["result"] != "failure" {
		t.Errorf("Expected result='failure', got %v", fields["result"])
	}
	if fields["reason"] != "invalid credentials" {
		t.Errorf("Expected reason='invalid credentials', got %v", fields["reason"])
	}
}

func TestLogAuthorizationFailure(t *testing.T) {
	logs, cleanup := setupTestSecurityLogger(zapcore.InfoLevel)
	defer cleanup()

	ctx := reqctx.SetRequestID(context.Background(), "test-request-authz")
	LogAuthorizationFailure(ctx, "jwt", "user@example.com", "/api/admin", "192.168.1.100", "insufficient permissions")

	if logs.Len() != 1 {
		t.Fatalf("Expected 1 log entry, got %d", logs.Len())
	}

	fields := fieldMap(logs.All()[0].ContextMap())
	if fields["event_type"] != SecurityEventAuthzDenied {
		t.Errorf("Expected event_type=%s, got %v", SecurityEventAuthzDenied, fields["event_type"])
	}
	if fields["resource"] != "/api/admin" {
		t.Errorf("Expected resource='/api/admin', got %v", fields["resource"])
	}
	if fields["reason"] != "insufficient permissions" {
		t.Errorf("Expected reason='insufficient permissions', got %v", fields["reason"])
	}
}

func TestLogRateLimitViolation(t *testing.T) {
	logs, cleanup := setupTestSecurityLogger(zapcore.InfoLevel)
	defer cleanup()

	ctx := reqctx.SetRequestID(context.Background(), "test-request-rate")
	LogRateLimitViolation(ctx, "per_minute", "192.168.1.100", "user123", 100, "1m")

	if logs.Len() != 1 {
		t.Fatalf("Expected 1 log entry, got %d", logs.Len())
	}

	fields := fieldMap(logs.All()[0].ContextMap())
	if fields["event_type"] != SecurityEventRateLimit {
		t.Errorf("Expected event_type=%s, got %v", SecurityEventRateLimit, fields["event_type"])
	}
	if fields["rate_limit_type"] != "per_minute" {
		t.Errorf("Expected rate_limit_type='per_minute', got %v", fields["rate_limit_type"])
	}

	// limit is int, observer stores as int64
	if v, ok := fields["limit"].(int64); !ok || v != 100 {
		t.Errorf("Expected limit=100, got %v (%T)", fields["limit"], fields["limit"])
	}

	if fields["window"] != "1m" {
		t.Errorf("Expected window='1m', got %v", fields["window"])
	}
}

func TestLogThreatDetected(t *testing.T) {
	logs, cleanup := setupTestSecurityLogger(zapcore.InfoLevel)
	defer cleanup()

	ctx := reqctx.SetRequestID(context.Background(), "test-request-threat")
	details := map[string]any{
		"attack_type":     "sql_injection",
		"pattern_matched": "' OR '1'='1",
	}
	LogThreatDetected(ctx, "sql_injection", "10.0.0.1", details)

	if logs.Len() != 1 {
		t.Fatalf("Expected 1 log entry, got %d", logs.Len())
	}

	fields := fieldMap(logs.All()[0].ContextMap())
	if fields["event_type"] != SecurityEventThreatDetected {
		t.Errorf("Expected event_type=%s, got %v", SecurityEventThreatDetected, fields["event_type"])
	}
	if fields["threat_type"] != "sql_injection" {
		t.Errorf("Expected threat_type='sql_injection', got %v", fields["threat_type"])
	}
}

func TestLogConfigChange(t *testing.T) {
	logs, cleanup := setupTestSecurityLogger(zapcore.InfoLevel)
	defer cleanup()

	ctx := reqctx.SetRequestID(context.Background(), "test-request-config")
	changes := map[string]any{
		"field":     "rate_limit",
		"old_value": 100,
		"new_value": 200,
	}
	LogConfigChange(ctx, "origin", "origin-123", "update", "admin@example.com", changes)

	if logs.Len() != 1 {
		t.Fatalf("Expected 1 log entry, got %d", logs.Len())
	}

	fields := fieldMap(logs.All()[0].ContextMap())
	if fields["event_type"] != SecurityEventConfigChange {
		t.Errorf("Expected event_type=%s, got %v", SecurityEventConfigChange, fields["event_type"])
	}
	if fields["action"] != "update" {
		t.Errorf("Expected action='update', got %v", fields["action"])
	}
	if fields["config_type"] != "origin" {
		t.Errorf("Expected config_type='origin', got %v", fields["config_type"])
	}
	if fields["admin_user"] != "admin@example.com" {
		t.Errorf("Expected admin_user='admin@example.com', got %v", fields["admin_user"])
	}
}

func TestLogAdminAction(t *testing.T) {
	logs, cleanup := setupTestSecurityLogger(zapcore.InfoLevel)
	defer cleanup()

	ctx := reqctx.SetRequestID(context.Background(), "test-request-admin")
	details := map[string]any{
		"reason": "too many failed attempts",
	}
	LogAdminAction(ctx, "unlock_account", "admin@example.com", "user@example.com", details)

	if logs.Len() != 1 {
		t.Fatalf("Expected 1 log entry, got %d", logs.Len())
	}

	fields := fieldMap(logs.All()[0].ContextMap())
	if fields["event_type"] != SecurityEventAdminAction {
		t.Errorf("Expected event_type=%s, got %v", SecurityEventAdminAction, fields["event_type"])
	}
	if fields["action"] != "unlock_account" {
		t.Errorf("Expected action='unlock_account', got %v", fields["action"])
	}
	if fields["admin_user"] != "admin@example.com" {
		t.Errorf("Expected admin_user='admin@example.com', got %v", fields["admin_user"])
	}
	if fields["target"] != "user@example.com" {
		t.Errorf("Expected target='user@example.com', got %v", fields["target"])
	}
}

func TestLogAccountLocked(t *testing.T) {
	logs, cleanup := setupTestSecurityLogger(zapcore.InfoLevel)
	defer cleanup()

	ctx := reqctx.SetRequestID(context.Background(), "test-request-lock")
	LogAccountLocked(ctx, "user@example.com", "192.168.1.100", 5, "15m")

	if logs.Len() != 1 {
		t.Fatalf("Expected 1 log entry, got %d", logs.Len())
	}

	fields := fieldMap(logs.All()[0].ContextMap())
	if fields["event_type"] != SecurityEventAccountLocked {
		t.Errorf("Expected event_type=%s, got %v", SecurityEventAccountLocked, fields["event_type"])
	}
	if fields["severity"] != SeverityHigh {
		t.Errorf("Expected severity=%s, got %v", SeverityHigh, fields["severity"])
	}
	if v, ok := fields["failed_attempts"].(int64); !ok || v != 5 {
		t.Errorf("Expected failed_attempts=5, got %v (%T)", fields["failed_attempts"], fields["failed_attempts"])
	}
	if fields["lock_duration"] != "15m" {
		t.Errorf("Expected lock_duration='15m', got %v", fields["lock_duration"])
	}
}

func TestSeverityLogLevels(t *testing.T) {
	tests := []struct {
		name          string
		severity      string
		expectedLevel zapcore.Level
	}{
		{"Critical uses Error", SeverityCritical, zapcore.ErrorLevel},
		{"High uses Warn", SeverityHigh, zapcore.WarnLevel},
		{"Medium uses Info", SeverityMedium, zapcore.InfoLevel},
		{"Low uses Info", SeverityLow, zapcore.InfoLevel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs, cleanup := setupTestSecurityLogger(zapcore.DebugLevel)
			defer cleanup()

			ctx := context.Background()
			LogSecurityEvent(ctx, SecurityEventAuthFailure, tt.severity, "test", "test")

			if logs.Len() != 1 {
				t.Fatalf("Expected 1 log entry, got %d", logs.Len())
			}

			entry := logs.All()[0]
			if entry.Level != tt.expectedLevel {
				t.Errorf("Expected level=%v for severity=%s, got %v", tt.expectedLevel, tt.severity, entry.Level)
			}
		})
	}
}

// fieldMap converts observer's ContextMap to a flat map for assertions.
func fieldMap(m map[string]any) map[string]any {
	// The observer already returns a flat map of field name → value.
	// Marshal and unmarshal to normalize types (e.g., int vs int64).
	b, _ := json.Marshal(m)
	var result map[string]any
	_ = json.Unmarshal(b, &result)
	// Merge back integer types from original for precise assertions
	for k, v := range m {
		if _, ok := result[k]; !ok {
			result[k] = v
		}
	}
	return m
}
