// Package events implements a publish-subscribe event bus for system observability and inter-component communication.
package events

// WebSocketConnectionLifecycle fires when a proxied websocket session opens or closes.
type WebSocketConnectionLifecycle struct {
	EventBase
	ConnectionID    string  `json:"connection_id"`
	Path            string  `json:"path"`
	Provider        string  `json:"provider,omitempty"`
	State           string  `json:"state"`
	DurationSeconds float64 `json:"duration_seconds,omitempty"`
}

// WebSocketToolCall fires when an observed websocket message indicates a tool invocation lifecycle event.
type WebSocketToolCall struct {
	EventBase
	ConnectionID     string `json:"connection_id"`
	Path             string `json:"path"`
	Provider         string `json:"provider,omitempty"`
	Direction        string `json:"direction"`
	MessageEventType string `json:"event_type"`
}
