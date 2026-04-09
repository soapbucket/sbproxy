package streaming

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultMediator bridges HTTP, SSE, and WebSocket protocols to a streaming backend.
type DefaultMediator struct {
	producer  Producer
	consumer  Consumer
	validator SchemaValidator
}

// NewMediator creates a new DefaultMediator with the given producer, consumer, and optional validator.
func NewMediator(producer Producer, consumer Consumer, validator SchemaValidator) *DefaultMediator {
	return &DefaultMediator{
		producer:  producer,
		consumer:  consumer,
		validator: validator,
	}
}

// HTTPToStream validates the payload (if a validator is set) and publishes a message to the stream.
func (m *DefaultMediator) HTTPToStream(ctx context.Context, topic string, key, value []byte, headers map[string]string) error {
	if m.validator != nil {
		if err := m.validator.Validate(value); err != nil {
			return fmt.Errorf("streaming: validation failed: %w", err)
		}
	}

	msg := Message{
		Key:       key,
		Value:     value,
		Headers:   headers,
		Topic:     topic,
		Timestamp: time.Now(),
	}

	if err := m.producer.Publish(ctx, msg); err != nil {
		return fmt.Errorf("streaming: publish failed: %w", err)
	}

	return nil
}

// StreamToSSE subscribes to a topic and streams messages as Server-Sent Events.
// It blocks until the context is cancelled or an unrecoverable error occurs.
func (m *DefaultMediator) StreamToSSE(ctx context.Context, topic string, w http.ResponseWriter) error {
	if err := m.consumer.Subscribe(ctx, []string{topic}); err != nil {
		return fmt.Errorf("streaming: subscribe failed: %w", err)
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		return fmt.Errorf("streaming: response writer does not support flushing")
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		msg, err := m.consumer.Read(ctx)
		if err != nil {
			if err == io.EOF {
				// No messages available, continue polling.
				continue
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("streaming: read failed: %w", err)
		}

		event := sseEvent{
			Topic:     msg.Topic,
			Partition: msg.Partition,
			Offset:    msg.Offset,
			Key:       string(msg.Key),
			Value:     json.RawMessage(msg.Value),
			Timestamp: msg.Timestamp,
		}

		data, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("streaming: failed to marshal SSE event: %w", err)
		}

		_, writeErr := fmt.Fprintf(w, "data: %s\n\n", data)
		if writeErr != nil {
			return fmt.Errorf("streaming: failed to write SSE event: %w", writeErr)
		}
		flusher.Flush()

		if commitErr := m.consumer.Commit(ctx, msg); commitErr != nil {
			return fmt.Errorf("streaming: commit failed: %w", commitErr)
		}
	}
}

// sseEvent is the JSON structure written to SSE clients.
type sseEvent struct {
	Topic     string          `json:"topic"`
	Partition int             `json:"partition"`
	Offset    int64           `json:"offset"`
	Key       string          `json:"key,omitempty"`
	Value     json.RawMessage `json:"value"`
	Timestamp time.Time       `json:"timestamp,omitempty"`
}

// StreamToWebSocket subscribes to a topic and sends messages over a WebSocket connection.
// It blocks until the context is cancelled or an unrecoverable error occurs.
func (m *DefaultMediator) StreamToWebSocket(ctx context.Context, topic string, conn WebSocketConn) error {
	if err := m.consumer.Subscribe(ctx, []string{topic}); err != nil {
		return fmt.Errorf("streaming: subscribe failed: %w", err)
	}

	// TextMessage type = 1 (standard WebSocket text frame).
	const textMessage = 1

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		msg, err := m.consumer.Read(ctx)
		if err != nil {
			if err == io.EOF {
				continue
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("streaming: read failed: %w", err)
		}

		event := sseEvent{
			Topic:     msg.Topic,
			Partition: msg.Partition,
			Offset:    msg.Offset,
			Key:       string(msg.Key),
			Value:     json.RawMessage(msg.Value),
			Timestamp: msg.Timestamp,
		}

		data, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("streaming: failed to marshal WebSocket event: %w", err)
		}

		if writeErr := conn.WriteMessage(textMessage, data); writeErr != nil {
			return fmt.Errorf("streaming: failed to write WebSocket message: %w", writeErr)
		}

		if commitErr := m.consumer.Commit(ctx, msg); commitErr != nil {
			return fmt.Errorf("streaming: commit failed: %w", commitErr)
		}
	}
}

// Close shuts down both the producer and consumer.
func (m *DefaultMediator) Close() error {
	var errs []error
	if m.producer != nil {
		if err := m.producer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if m.consumer != nil {
		if err := m.consumer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("streaming: close errors: %v", errs)
	}
	return nil
}
