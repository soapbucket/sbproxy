// types.go defines core streaming types including Message, Producer, and Consumer interfaces.
package streaming

import (
	"context"
	"net/http"
	"time"
)

// Message represents a streaming message.
type Message struct {
	Key       []byte            `json:"key,omitempty"`
	Value     []byte            `json:"value"`
	Headers   map[string]string `json:"headers,omitempty"`
	Topic     string            `json:"topic"`
	Partition int               `json:"partition,omitempty"`
	Offset    int64             `json:"offset,omitempty"`
	Timestamp time.Time         `json:"timestamp,omitempty"`
}

// Producer publishes messages to a streaming backend.
type Producer interface {
	Publish(ctx context.Context, msg Message) error
	Close() error
}

// Consumer reads messages from a streaming backend.
type Consumer interface {
	Subscribe(ctx context.Context, topics []string) error
	Read(ctx context.Context) (Message, error)
	Commit(ctx context.Context, msg Message) error
	Close() error
}

// Mediator bridges between protocols (HTTP <-> streaming).
type Mediator interface {
	// HTTPToStream accepts HTTP POST and publishes to stream.
	HTTPToStream(ctx context.Context, topic string, key, value []byte, headers map[string]string) error
	// StreamToSSE reads from stream and writes SSE events to an http.ResponseWriter.
	StreamToSSE(ctx context.Context, topic string, w http.ResponseWriter) error
	// StreamToWebSocket reads from stream and writes to a WebSocket connection.
	StreamToWebSocket(ctx context.Context, topic string, conn WebSocketConn) error
	Close() error
}

// WebSocketConn is a minimal interface for WebSocket connections.
type WebSocketConn interface {
	WriteMessage(messageType int, data []byte) error
	ReadMessage() (messageType int, data []byte, err error)
	Close() error
}

// SchemaValidator validates event payloads.
type SchemaValidator interface {
	Validate(data []byte) error
}
