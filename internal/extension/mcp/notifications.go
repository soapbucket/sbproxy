// notifications.go defines MCP notification types and a queue for pending notifications.
package mcp

import (
	"encoding/json"
	"sync"
)

// NotificationType constants for MCP notifications.
const (
	NotificationToolsListChanged     = "notifications/tools/list_changed"
	NotificationResourcesListChanged = "notifications/resources/list_changed"
	NotificationPromptsListChanged   = "notifications/prompts/list_changed"
	NotificationMessage              = "notifications/message"
)

// Notification represents a pending MCP notification to be sent to clients.
type Notification struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// LogMessageParams contains parameters for a notifications/message log notification.
type LogMessageParams struct {
	Level  string `json:"level"`  // debug, info, warning, error, critical, alert, emergency
	Logger string `json:"logger,omitempty"`
	Data   interface{} `json:"data,omitempty"`
}

// NotificationQueue buffers notifications for delivery to connected clients.
// In the current HTTP+JSON-RPC transport, notifications are polled by clients.
// With streamable HTTP transport, they would be pushed via the open connection.
type NotificationQueue struct {
	pending []Notification
	mu      sync.Mutex
	maxSize int
}

// NewNotificationQueue creates a new notification queue.
func NewNotificationQueue(maxSize int) *NotificationQueue {
	if maxSize <= 0 {
		maxSize = 100
	}
	return &NotificationQueue{
		pending: make([]Notification, 0),
		maxSize: maxSize,
	}
}

// Enqueue adds a notification to the queue.
func (q *NotificationQueue) Enqueue(method string, params interface{}) {
	q.mu.Lock()
	defer q.mu.Unlock()

	var paramsBytes json.RawMessage
	if params != nil {
		if data, err := json.Marshal(params); err == nil {
			paramsBytes = data
		}
	}

	n := Notification{
		JSONRPC: "2.0",
		Method:  method,
		Params:  paramsBytes,
	}

	// Drop oldest if at capacity
	if len(q.pending) >= q.maxSize {
		q.pending = q.pending[1:]
	}

	q.pending = append(q.pending, n)
}

// Drain returns and removes all pending notifications.
func (q *NotificationQueue) Drain() []Notification {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.pending) == 0 {
		return nil
	}

	result := q.pending
	q.pending = make([]Notification, 0)
	return result
}

// Size returns the number of pending notifications.
func (q *NotificationQueue) Size() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pending)
}

// EmitToolsListChanged enqueues a tools/list_changed notification.
func (q *NotificationQueue) EmitToolsListChanged() {
	q.Enqueue(NotificationToolsListChanged, nil)
}

// EmitResourcesListChanged enqueues a resources/list_changed notification.
func (q *NotificationQueue) EmitResourcesListChanged() {
	q.Enqueue(NotificationResourcesListChanged, nil)
}

// EmitLogMessage enqueues a log message notification.
func (q *NotificationQueue) EmitLogMessage(level, logger string, data interface{}) {
	q.Enqueue(NotificationMessage, &LogMessageParams{
		Level:  level,
		Logger: logger,
		Data:   data,
	})
}
