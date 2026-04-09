package audit

import (
	"testing"
)

func TestAuditEventType_IsValid(t *testing.T) {
	tests := []struct {
		name      string
		eventType AuditEventType
		want      bool
	}{
		{name: "KeyCreated", eventType: KeyCreated, want: true},
		{name: "KeyRevoked", eventType: KeyRevoked, want: true},
		{name: "KeyRotated", eventType: KeyRotated, want: true},
		{name: "EntitlementChanged", eventType: EntitlementChanged, want: true},
		{name: "PolicyModified", eventType: PolicyModified, want: true},
		{name: "GuardrailTriggered", eventType: GuardrailTriggered, want: true},
		{name: "AccessDenied", eventType: AccessDenied, want: true},
		{name: "ConfigChanged", eventType: ConfigChanged, want: true},
		{name: "ExportRequested", eventType: ExportRequested, want: true},
		{name: "LoginAttempt", eventType: LoginAttempt, want: true},
		{name: "empty string", eventType: "", want: false},
		{name: "unknown type", eventType: "unknown.event", want: false},
		{name: "partial match", eventType: "key", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.eventType.IsValid()
			if got != tt.want {
				t.Errorf("AuditEventType(%q).IsValid() = %v, want %v", tt.eventType, got, tt.want)
			}
		})
	}
}

func TestValidEventTypes_Count(t *testing.T) {
	// Ensure all 10 event types are registered.
	if got := len(ValidEventTypes); got != 10 {
		t.Errorf("ValidEventTypes has %d entries, want 10", got)
	}
}

func TestAuditEventType_StringValues(t *testing.T) {
	// Verify the string values use dot notation.
	tests := []struct {
		eventType AuditEventType
		wantStr   string
	}{
		{KeyCreated, "key.created"},
		{KeyRevoked, "key.revoked"},
		{KeyRotated, "key.rotated"},
		{EntitlementChanged, "entitlement.changed"},
		{PolicyModified, "policy.modified"},
		{GuardrailTriggered, "guardrail.triggered"},
		{AccessDenied, "access.denied"},
		{ConfigChanged, "config.changed"},
		{ExportRequested, "export.requested"},
		{LoginAttempt, "login.attempt"},
	}

	for _, tt := range tests {
		t.Run(tt.wantStr, func(t *testing.T) {
			if string(tt.eventType) != tt.wantStr {
				t.Errorf("got %q, want %q", string(tt.eventType), tt.wantStr)
			}
		})
	}
}
