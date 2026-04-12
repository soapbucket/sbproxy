package streaming

import (
	"context"
	"errors"
	"testing"
)

// mockProducer is a test double for the Producer interface.
type mockProducer struct {
	published []Message
	err       error
	closed    bool
}

func (m *mockProducer) Publish(_ context.Context, msg Message) error {
	if m.err != nil {
		return m.err
	}
	m.published = append(m.published, msg)
	return nil
}

func (m *mockProducer) Close() error {
	m.closed = true
	return nil
}

// mockConsumer is a test double for the Consumer interface.
type mockConsumer struct {
	subscribeTopics []string
	messages        []Message
	readIndex       int
	commitCalled    int
	subscribeErr    error
	readErr         error
	closed          bool
}

func (m *mockConsumer) Subscribe(_ context.Context, topics []string) error {
	if m.subscribeErr != nil {
		return m.subscribeErr
	}
	m.subscribeTopics = topics
	return nil
}

func (m *mockConsumer) Read(_ context.Context) (Message, error) {
	if m.readErr != nil {
		return Message{}, m.readErr
	}
	if m.readIndex >= len(m.messages) {
		return Message{}, errors.New("no more messages")
	}
	msg := m.messages[m.readIndex]
	m.readIndex++
	return msg, nil
}

func (m *mockConsumer) Commit(_ context.Context, _ Message) error {
	m.commitCalled++
	return nil
}

func (m *mockConsumer) Close() error {
	m.closed = true
	return nil
}

// failingValidator always returns an error.
type failingValidator struct {
	err error
}

func (v *failingValidator) Validate(_ []byte) error {
	return v.err
}

func TestMediator_HTTPToStream(t *testing.T) {
	prod := &mockProducer{}
	cons := &mockConsumer{}
	mediator := NewMediator(prod, cons, nil)

	ctx := context.Background()
	key := []byte("order-123")
	value := []byte(`{"action":"created","amount":99.99}`)
	headers := map[string]string{"X-Trace-ID": "abc-123"}

	err := mediator.HTTPToStream(ctx, "orders", key, value, headers)
	if err != nil {
		t.Fatalf("HTTPToStream failed: %v", err)
	}

	if len(prod.published) != 1 {
		t.Fatalf("expected 1 published message, got %d", len(prod.published))
	}

	msg := prod.published[0]
	if msg.Topic != "orders" {
		t.Errorf("expected topic 'orders', got %q", msg.Topic)
	}
	if string(msg.Key) != "order-123" {
		t.Errorf("expected key 'order-123', got %q", string(msg.Key))
	}
	if string(msg.Value) != `{"action":"created","amount":99.99}` {
		t.Errorf("unexpected value: %s", string(msg.Value))
	}
	if msg.Headers["X-Trace-ID"] != "abc-123" {
		t.Errorf("expected header X-Trace-ID=abc-123, got %q", msg.Headers["X-Trace-ID"])
	}
	if msg.Timestamp.IsZero() {
		t.Error("expected timestamp to be set")
	}
}

func TestMediator_HTTPToStream_ValidationFailure(t *testing.T) {
	prod := &mockProducer{}
	cons := &mockConsumer{}
	validator := &failingValidator{err: errors.New("missing required field: user_id")}
	mediator := NewMediator(prod, cons, validator)

	ctx := context.Background()
	err := mediator.HTTPToStream(ctx, "events", nil, []byte(`{"bad":"data"}`), nil)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}

	if len(prod.published) != 0 {
		t.Error("expected no messages to be published after validation failure")
	}
}

func TestMediator_HTTPToStream_ProducerError(t *testing.T) {
	prod := &mockProducer{err: errors.New("connection refused")}
	cons := &mockConsumer{}
	mediator := NewMediator(prod, cons, nil)

	ctx := context.Background()
	err := mediator.HTTPToStream(ctx, "events", nil, []byte(`{"ok":true}`), nil)
	if err == nil {
		t.Fatal("expected publish error, got nil")
	}
}

func TestMediator_Close(t *testing.T) {
	prod := &mockProducer{}
	cons := &mockConsumer{}
	mediator := NewMediator(prod, cons, nil)

	if err := mediator.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	if !prod.closed {
		t.Error("expected producer to be closed")
	}
	if !cons.closed {
		t.Error("expected consumer to be closed")
	}
}
