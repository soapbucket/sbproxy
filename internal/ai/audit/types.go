// Package audit provides immutable audit logging for the AI gateway.
package audit

import (
	"time"
)

// AuditEventType identifies the kind of auditable action.
type AuditEventType string

const (
	// KeyCreated is logged when an API key is created.
	KeyCreated AuditEventType = "key.created"
	// KeyRevoked is logged when an API key is revoked.
	KeyRevoked AuditEventType = "key.revoked"
	// KeyRotated is logged when an API key is rotated.
	KeyRotated AuditEventType = "key.rotated"
	// EntitlementChanged is logged when entitlements are modified.
	EntitlementChanged AuditEventType = "entitlement.changed"
	// PolicyModified is logged when a policy is created, updated, or deleted.
	PolicyModified AuditEventType = "policy.modified"
	// GuardrailTriggered is logged when a guardrail fires.
	GuardrailTriggered AuditEventType = "guardrail.triggered"
	// AccessDenied is logged when a request is denied by policy.
	AccessDenied AuditEventType = "access.denied"
	// ConfigChanged is logged when gateway configuration changes.
	ConfigChanged AuditEventType = "config.changed"
	// ExportRequested is logged when an audit export is requested.
	ExportRequested AuditEventType = "export.requested"
	// LoginAttempt is logged for authentication attempts.
	LoginAttempt AuditEventType = "login.attempt"
)

// ValidEventTypes contains all recognized audit event types.
var ValidEventTypes = map[AuditEventType]bool{
	KeyCreated:         true,
	KeyRevoked:         true,
	KeyRotated:         true,
	EntitlementChanged: true,
	PolicyModified:     true,
	GuardrailTriggered: true,
	AccessDenied:       true,
	ConfigChanged:      true,
	ExportRequested:    true,
	LoginAttempt:       true,
}

// IsValid returns true if the event type is recognized.
func (t AuditEventType) IsValid() bool {
	return ValidEventTypes[t]
}

// ActorType identifies what kind of entity performed the action.
type ActorType string

const (
	// ActorUser is a human user.
	ActorUser ActorType = "user"
	// ActorSystem is an automated system process.
	ActorSystem ActorType = "system"
	// ActorAPI is an API client.
	ActorAPI ActorType = "api"
)

// AuditEvent is an immutable record of an auditable action.
type AuditEvent struct {
	ID          string         `json:"id"`
	Timestamp   time.Time      `json:"timestamp"`
	WorkspaceID string         `json:"workspace_id"`
	Type        AuditEventType `json:"type"`
	ActorID     string         `json:"actor_id"`
	ActorType   string         `json:"actor_type"`
	TargetType  string         `json:"target_type,omitempty"`
	TargetID    string         `json:"target_id,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
	IPAddress   string         `json:"ip_address,omitempty"`
	UserAgent   string         `json:"user_agent,omitempty"`
}

// AuditQuery defines filters for querying audit events.
type AuditQuery struct {
	WorkspaceID string           `json:"workspace_id,omitempty"`
	Types       []AuditEventType `json:"types,omitempty"`
	ActorID     string           `json:"actor_id,omitempty"`
	TargetID    string           `json:"target_id,omitempty"`
	StartTime   time.Time        `json:"start_time,omitempty"`
	EndTime     time.Time        `json:"end_time,omitempty"`
	Limit       int              `json:"limit,omitempty"`
	Offset      int              `json:"offset,omitempty"`
}
