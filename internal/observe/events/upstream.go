// Package events implements a publish-subscribe event bus for system observability and inter-component communication.
package events

// UpstreamTimeout fires when an upstream request times out
type UpstreamTimeout struct {
	EventBase
	UpstreamURL    string `json:"upstream_url"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	Path           string `json:"path"`
}

// Upstream5xx fires when an upstream returns a server error
type Upstream5xx struct {
	EventBase
	UpstreamURL    string `json:"upstream_url"`
	StatusCode     int    `json:"status_code"`
	Path           string `json:"path"`
	ResponseTimeMS int64  `json:"response_time_ms"`
}

// CircuitOpened fires when a circuit breaker trips
type CircuitOpened struct {
	EventBase
	UpstreamURL     string `json:"upstream_url"`
	FailureCount    int    `json:"failure_count"`
	CooldownSeconds int    `json:"cooldown_seconds"`
}

// CircuitClosed fires when a circuit breaker recovers
type CircuitClosed struct {
	EventBase
	UpstreamURL         string `json:"upstream_url"`
	RecoveryTimeSeconds int    `json:"recovery_time_seconds"`
}

// HealthChange fires when a load balancer target transitions between healthy and unhealthy.
type HealthChange struct {
	EventBase
	Target string `json:"target"`
	Status string `json:"status"` // "healthy" or "unhealthy"
}
