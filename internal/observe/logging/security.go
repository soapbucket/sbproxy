// Package logging handles structured request logging to multiple backends (stdout, ClickHouse, file).
package logging

import (
	"context"

	"go.uber.org/zap"
	"go.opentelemetry.io/otel/trace"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// Security Event Types
const (
	// SecurityEventAuthSuccess is a constant for security event auth success.
	SecurityEventAuthSuccess       = "authentication_success"
	// SecurityEventAuthFailure is a constant for security event auth failure.
	SecurityEventAuthFailure       = "authentication_failure"
	// SecurityEventAuthzDenied is a constant for security event authz denied.
	SecurityEventAuthzDenied       = "authorization_denied"
	// SecurityEventRateLimit is a constant for security event rate limit.
	SecurityEventRateLimit         = "rate_limit_exceeded"
	// SecurityEventThreatDetected is a constant for security event threat detected.
	SecurityEventThreatDetected    = "threat_detected"
	// SecurityEventSuspiciousPattern is a constant for security event suspicious pattern.
	SecurityEventSuspiciousPattern = "suspicious_pattern_detected"
	// SecurityEventConfigChange is a constant for security event config change.
	SecurityEventConfigChange      = "configuration_change"
	// SecurityEventAdminAction is a constant for security event admin action.
	SecurityEventAdminAction       = "admin_action"
	// SecurityEventAccountLocked is a constant for security event account locked.
	SecurityEventAccountLocked     = "account_locked"
	// SecurityEventAccountUnlocked is a constant for security event account unlocked.
	SecurityEventAccountUnlocked   = "account_unlocked"
	// SecurityEventCSRFViolation is a constant for security event csrf violation.
	SecurityEventCSRFViolation     = "csrf_validation_failure"
	// SecurityEventInputValidation is a constant for security event input validation.
	SecurityEventInputValidation   = "input_validation_failure"
	// SecurityEventGeoBlock is a constant for security event geo block.
	SecurityEventGeoBlock          = "geo_block_violation"
	// SecurityEventIPBlocked is a constant for security event ip blocked.
	SecurityEventIPBlocked         = "ip_blocked"
	// SecurityEventDDoSAttack is a constant for security event d do s attack.
	SecurityEventDDoSAttack        = "ddos_attack_detected"
	// SecurityEventAIGuardrail is a constant for AI safety guardrail violations.
	SecurityEventAIGuardrail       = "ai_guardrail_triggered"
	// SecurityEventAIPII is a constant for PII detected in AI requests.
	SecurityEventAIPII             = "ai_pii_detected"
	// SecurityEventAIInjection is a constant for prompt injection detected.
	SecurityEventAIInjection       = "ai_prompt_injection"
	// SecurityEventAIBudget is a constant for AI budget limit exceeded.
	SecurityEventAIBudget          = "ai_budget_exceeded"
)

// Security Event Severity Levels
const (
	// SeverityLow is a constant for severity low.
	SeverityLow      = "low"
	// SeverityMedium is a constant for severity medium.
	SeverityMedium   = "medium"
	// SeverityHigh is a constant for severity high.
	SeverityHigh     = "high"
	// SeverityCritical is a constant for severity critical.
	SeverityCritical = "critical"
)

// LogSecurityEvent logs a security event using native zap.
func LogSecurityEvent(
	ctx context.Context,
	eventType string,
	severity string,
	action string,
	result string,
	extraFields ...zap.Field,
) {
	logger := GetZapSecurityLogger()
	if logger == nil {
		return
	}

	fields := make([]zap.Field, 0, 8+len(extraFields))
	fields = append(fields,
		zap.String(FieldSecurityEventType, eventType),
		zap.String(FieldSeverity, severity),
		zap.String(FieldAction, action),
		zap.String(FieldResult, result),
	)

	// Request ID from context
	requestID := reqctx.GetRequestID(ctx)
	if requestID != "" {
		fields = append(fields, zap.String(FieldRequestID, requestID))
	}

	// Origin info from context
	if requestData := reqctx.GetRequestData(ctx); requestData != nil && requestData.Config != nil {
		configParams := reqctx.ConfigParams(requestData.Config)
		fields = append(fields,
			zap.String(FieldConfigID, configParams.GetConfigID()),
			zap.String(FieldWorkspaceID, configParams.GetWorkspaceID()),
		)
	}

	// Tracing
	spanCtx := trace.SpanContextFromContext(ctx)
	if spanCtx.IsValid() {
		fields = append(fields,
			zap.String(FieldTraceID, spanCtx.TraceID().String()),
			zap.String(FieldSpanID, spanCtx.SpanID().String()),
		)
	}

	fields = append(fields, extraFields...)

	switch severity {
	case SeverityCritical:
		logger.Error("security event", fields...)
	case SeverityHigh:
		logger.Warn("security event", fields...)
	default:
		logger.Info("security event", fields...)
	}
}

// LogAuthenticationAttempt logs authentication attempts.
func LogAuthenticationAttempt(ctx context.Context, success bool, authType, username, ip, reason string) {
	eventType := SecurityEventAuthSuccess
	severity := SeverityMedium
	result := "success"
	if !success {
		eventType = SecurityEventAuthFailure
		severity = SeverityHigh
		result = "failure"
	}

	fields := []zap.Field{
		zap.String("auth_type", authType),
		zap.String("username", username),
		zap.String("ip", ip),
	}
	if reason != "" {
		fields = append(fields, zap.String("reason", reason))
	}

	LogSecurityEvent(ctx, eventType, severity, "authenticate", result, fields...)
}

// LogAuthorizationFailure logs authorization failures.
func LogAuthorizationFailure(ctx context.Context, authType, username, resource, ip, reason string) {
	LogSecurityEvent(ctx, SecurityEventAuthzDenied, SeverityHigh, "authorize", "denied",
		zap.String("auth_type", authType),
		zap.String("username", username),
		zap.String("resource", resource),
		zap.String("ip", ip),
		zap.String("reason", reason),
	)
}

// LogRateLimitViolation logs rate limit violations.
func LogRateLimitViolation(ctx context.Context, rateLimitType, ip, userID string, limit int, window string) {
	fields := []zap.Field{
		zap.String("rate_limit_type", rateLimitType),
		zap.String("ip", ip),
		zap.Int("limit", limit),
		zap.String("window", window),
	}
	if userID != "" {
		fields = append(fields, zap.String("user_id", userID))
	}
	LogSecurityEvent(ctx, SecurityEventRateLimit, SeverityMedium, "rate_limit_check", "violated", fields...)
}

// LogThreatDetected logs threat detections.
func LogThreatDetected(ctx context.Context, threatType, ip string, details map[string]any) {
	fields := []zap.Field{
		zap.String("threat_type", threatType),
		zap.String("ip", ip),
	}
	if details != nil {
		fields = append(fields, zap.Any("details", details))
	}
	LogSecurityEvent(ctx, SecurityEventThreatDetected, SeverityHigh, "threat_detection", "detected", fields...)
}

// LogSuspiciousPattern logs suspicious pattern detections.
func LogSuspiciousPattern(ctx context.Context, patternType, ip string, details map[string]any) {
	fields := []zap.Field{
		zap.String("pattern_type", patternType),
		zap.String("ip", ip),
	}
	if details != nil {
		fields = append(fields, zap.Any("details", details))
	}
	LogSecurityEvent(ctx, SecurityEventSuspiciousPattern, SeverityMedium, "pattern_detection", "detected", fields...)
}

// LogConfigChange logs configuration changes.
func LogConfigChange(ctx context.Context, configType, configID, action, adminUser string, changes map[string]any) {
	fields := []zap.Field{
		zap.String("config_type", configType),
		zap.String("config_id", configID),
		zap.String("admin_user", adminUser),
	}
	if changes != nil {
		fields = append(fields, zap.Any("changes", changes))
	}
	LogSecurityEvent(ctx, SecurityEventConfigChange, SeverityMedium, action, "success", fields...)
}

// LogAdminAction logs admin actions.
func LogAdminAction(ctx context.Context, action, adminUser, target string, details map[string]any) {
	fields := []zap.Field{
		zap.String("admin_user", adminUser),
		zap.String("target", target),
	}
	if details != nil {
		fields = append(fields, zap.Any("details", details))
	}
	LogSecurityEvent(ctx, SecurityEventAdminAction, SeverityMedium, action, "success", fields...)
}

// LogAccountLocked logs when an account is locked.
func LogAccountLocked(ctx context.Context, username, ip string, failedAttempts int, lockDuration string) {
	LogSecurityEvent(ctx, SecurityEventAccountLocked, SeverityHigh, "lock_account", "locked",
		zap.String("username", username),
		zap.String("ip", ip),
		zap.Int("failed_attempts", failedAttempts),
		zap.String("lock_duration", lockDuration),
	)
}

// LogAccountUnlocked logs when an account is unlocked.
func LogAccountUnlocked(ctx context.Context, username, adminUser, reason string) {
	LogSecurityEvent(ctx, SecurityEventAccountUnlocked, SeverityMedium, "unlock_account", "unlocked",
		zap.String("username", username),
		zap.String("admin_user", adminUser),
		zap.String("reason", reason),
	)
}

// LogGeoBlock logs geo-blocking events.
func LogGeoBlock(ctx context.Context, ip, country, resource string) {
	LogSecurityEvent(ctx, SecurityEventGeoBlock, SeverityMedium, "geo_check", "blocked",
		zap.String("ip", ip),
		zap.String("country", country),
		zap.String("resource", resource),
	)
}

// LogIPBlocked logs IP blocking events.
func LogIPBlocked(ctx context.Context, ip, reason, resource string) {
	LogSecurityEvent(ctx, SecurityEventIPBlocked, SeverityHigh, "ip_check", "blocked",
		zap.String("ip", ip),
		zap.String("reason", reason),
		zap.String("resource", resource),
	)
}

// LogAIGuardrailTriggered logs when an AI guardrail blocks or flags content.
func LogAIGuardrailTriggered(ctx context.Context, guardrailType, action, phase, detail, model string) {
	severity := SeverityMedium
	result := "flagged"
	if action == "block" {
		severity = SeverityHigh
		result = "blocked"
	}
	LogSecurityEvent(ctx, SecurityEventAIGuardrail, severity, "guardrail_check", result,
		zap.String("guardrail_type", guardrailType),
		zap.String("guardrail_action", action),
		zap.String("phase", phase),
		zap.String("detail", detail),
		zap.String("model", model),
	)
}

// LogAIPIIDetected logs when PII is detected in AI requests or responses.
func LogAIPIIDetected(ctx context.Context, action, phase, piiTypes, model string) {
	severity := SeverityHigh
	result := "detected"
	if action == "transform" {
		result = "redacted"
	}
	LogSecurityEvent(ctx, SecurityEventAIPII, severity, "pii_scan", result,
		zap.String("pii_action", action),
		zap.String("phase", phase),
		zap.String("pii_types", piiTypes),
		zap.String("model", model),
	)
}

// LogAIPromptInjection logs when prompt injection is detected.
func LogAIPromptInjection(ctx context.Context, action, detail, model string) {
	LogSecurityEvent(ctx, SecurityEventAIInjection, SeverityHigh, "injection_check", "detected",
		zap.String("injection_action", action),
		zap.String("detail", detail),
		zap.String("model", model),
	)
}

// LogAIBudgetExceeded logs when an AI budget limit is exceeded.
func LogAIBudgetExceeded(ctx context.Context, scope, scopeValue, period, actionTaken string, currentUSD, limitUSD float64) {
	LogSecurityEvent(ctx, SecurityEventAIBudget, SeverityMedium, "budget_check", "exceeded",
		zap.String("budget_scope", scope),
		zap.String("scope_value", scopeValue),
		zap.String("period", period),
		zap.String("action_taken", actionTaken),
		zap.Float64("current_usd", currentUSD),
		zap.Float64("limit_usd", limitUSD),
	)
}
