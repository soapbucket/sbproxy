// types.go defines the OriginContext and EventBase types used by all proxy events.
package events

import "time"

// OriginContext carries metadata about the origin that generated an event. It is
// embedded in [EventBase] so that every event includes full context about which
// origin, workspace, and environment it came from. This is essential for multi-tenant
// event filtering and routing.
type OriginContext struct {
	// OriginID is the unique identifier of the origin that emitted this event.
	OriginID string `json:"origin_id"`

	// OriginName is the human-readable name of the origin, used in logs and dashboards.
	OriginName string `json:"origin_name"`

	// Hostname is the public hostname the origin serves (e.g., "api.example.com").
	Hostname string `json:"hostname"`

	// VersionID is the configuration version that was active when the event occurred.
	VersionID string `json:"version_id"`

	// WorkspaceID identifies the tenant workspace, used for event isolation and routing.
	WorkspaceID string `json:"workspace_id"`

	// ActionType is the origin's action type (e.g., "proxy", "redirect") for filtering.
	ActionType string `json:"action_type"`

	// Environment is the deployment environment label (e.g., "production", "staging").
	Environment string `json:"environment"`

	// Tags are the origin's user-defined tags, copied here for event-side filtering
	// without needing to look up the origin configuration.
	Tags []string `json:"tags"`
}

// EventBase provides the common fields shared by all concrete event types. Embed
// this struct in your event type to automatically satisfy the [Event] interface
// and inherit standard fields like Type, Severity, and Timestamp.
//
//	type MyEvent struct {
//	    events.EventBase
//	    CustomField string `json:"custom_field"`
//	}
type EventBase struct {
	// Type is the dot-separated event type string (e.g., "request.completed").
	Type string `json:"type"`

	// Severity indicates the importance of this event. Use the Severity constants.
	Severity string `json:"severity"`

	// Timestamp is when the event occurred, set by the emitter.
	Timestamp time.Time `json:"timestamp"`

	// RequestID is the unique request identifier, if this event is associated with
	// a specific HTTP request. Empty for system-level events.
	RequestID string `json:"request_id,omitempty"`

	// Origin contains metadata about which origin emitted this event.
	Origin OriginContext `json:"origin"`
}

// EventType returns the event's type string, satisfying the [Event] interface.
func (e *EventBase) EventType() string { return e.Type }

// EventSeverity returns the event's severity level, satisfying the [Event] interface.
func (e *EventBase) EventSeverity() string { return e.Severity }

const (
	// SeverityCritical indicates a condition requiring immediate attention, such as
	// a security breach or complete service failure.
	SeverityCritical = "critical"

	// SeverityError indicates a failed operation that affects a single request or
	// origin but does not threaten overall service availability.
	SeverityError = "error"

	// SeverityWarning indicates a condition that may lead to errors if not addressed,
	// such as approaching a rate limit threshold or a degraded upstream.
	SeverityWarning = "warning"

	// SeverityInfo indicates normal operational events like configuration reloads,
	// successful health checks, or routine metrics.
	SeverityInfo = "info"
)

// Standard event type constants for proxy lifecycle events. Subscribe to these
// via [EventBus.Subscribe] to react to configuration and cache changes.
const (
	// TypeConfigReload is published after a configuration reload completes
	// (successfully or with errors). The event payload includes the hostname
	// and whether the reload succeeded.
	TypeConfigReload = "config.reload"

	// TypeConfigValidationError is published when a configuration fails validation
	// during a reload attempt.
	TypeConfigValidationError = "config.validation_error"

	// TypeCacheFlush is published when an origin's response cache is flushed,
	// either by API request, configuration change, or TTL expiration.
	TypeCacheFlush = "cache.flush"

	// TypeCacheEvict is published when individual cache entries are evicted
	// due to memory pressure or LRU policy.
	TypeCacheEvict = "cache.evict"

	// TypeOriginHealthChange is published when an upstream target transitions
	// between healthy and unhealthy states.
	TypeOriginHealthChange = "origin.health_change"
)

// ConfigReloadEvent carries details about a configuration reload.
type ConfigReloadEvent struct {
	EventBase

	// Hostname is the origin hostname that was reloaded.
	Hostname string `json:"hostname"`

	// Success indicates whether the reload completed without errors.
	Success bool `json:"success"`

	// Error contains the error message if Success is false.
	Error string `json:"error,omitempty"`
}

// CacheFlushEvent carries details about a cache flush operation.
type CacheFlushEvent struct {
	EventBase

	// Hostname is the origin hostname whose cache was flushed.
	Hostname string `json:"hostname"`

	// Reason describes why the cache was flushed (e.g., "api_request",
	// "config_change", "ttl_expiration").
	Reason string `json:"reason"`

	// EntriesRemoved is the number of cache entries that were evicted.
	EntriesRemoved int64 `json:"entries_removed"`
}
