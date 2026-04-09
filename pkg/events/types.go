package events

import "time"

// OriginContext identifies the origin that generated an event.
type OriginContext struct {
	OriginID    string   `json:"origin_id"`
	OriginName  string   `json:"origin_name"`
	Hostname    string   `json:"hostname"`
	VersionID   string   `json:"version_id"`
	WorkspaceID string   `json:"workspace_id"`
	ActionType  string   `json:"action_type"`
	Environment string   `json:"environment"`
	Tags        []string `json:"tags"`
}

// EventBase provides common fields for all events.
type EventBase struct {
	Type      string        `json:"type"`
	Severity  string        `json:"severity"`
	Timestamp time.Time     `json:"timestamp"`
	RequestID string        `json:"request_id,omitempty"`
	Origin    OriginContext `json:"origin"`
}

func (e *EventBase) EventType() string     { return e.Type }
func (e *EventBase) EventSeverity() string { return e.Severity }

const (
	SeverityCritical = "critical"
	SeverityError    = "error"
	SeverityWarning  = "warning"
	SeverityInfo     = "info"
)
