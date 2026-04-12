// Package events implements a publish-subscribe event bus for system observability and inter-component communication.
package events

import (
	"time"
)

// Severity levels for events
const (
	// SeverityCritical is a constant for severity critical.
	SeverityCritical = "critical" // budget exceeded, circuit opened
	// SeverityError is a constant for severity error.
	SeverityError = "error" // provider error, upstream 5xx, guardrail block
	// SeverityWarning is a constant for severity warning.
	SeverityWarning = "warning" // budget warning, model downgrade, latency spike
	// SeverityInfo is a constant for severity info.
	SeverityInfo = "info" // request completed, session started
)

// Event is the interface all events must implement
type Event interface {
	EventType() string
	EventSeverity() string
}

// EventBase carries common metadata for all events
type EventBase struct {
	Type      string        `json:"type"`
	Severity  string        `json:"severity"`
	Timestamp time.Time     `json:"timestamp"`
	RequestID string        `json:"request_id,omitempty"`
	Origin    OriginContext `json:"origin"`
}

// EventType performs the event type operation on the EventBase.
func (e EventBase) EventType() string { return e.Type }

// EventSeverity performs the event severity operation on the EventBase.
func (e EventBase) EventSeverity() string { return e.Severity }

// OriginContext identifies the source of the event
type OriginContext struct {
	OriginID    string   `json:"origin_id"`
	OriginName  string   `json:"origin_name"`
	Hostname    string   `json:"hostname"`
	VersionID   string   `json:"version_id"`
	WorkspaceID string   `json:"workspace_id"`
	ActionType  string   `json:"action_type"`
	Environment string   `json:"environment"`
	Tags        []string `json:"tags,omitempty"`
}

// NewBase creates a new EventBase with common fields populated
func NewBase(eventType string, severity string, workspaceID string, requestID string) EventBase {
	return EventBase{
		Type:      eventType,
		Severity:  severity,
		Timestamp: time.Now().UTC(),
		RequestID: requestID,
		Origin: OriginContext{
			WorkspaceID: workspaceID,
		},
	}
}
