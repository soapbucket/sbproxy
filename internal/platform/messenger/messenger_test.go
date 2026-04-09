package messenger

import (
	"context"
	"testing"
	"time"
)

func TestAvailableDrivers(t *testing.T) {
	t.Parallel()
	drivers := AvailableDrivers()
	expected := []string{DriverAWS, DriverGCP, DriverMemory, DriverNoop, DriverRedis}

	if len(drivers) != len(expected) {
		t.Errorf("Expected %d drivers, got %d", len(expected), len(drivers))
	}

	for _, expectedDriver := range expected {
		found := false
		for _, driver := range drivers {
			if driver == expectedDriver {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected driver %s not found in available drivers", expectedDriver)
		}
	}
}

func TestNewMessenger(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		settings Settings
		wantErr  bool
	}{
		{
			name: "memory driver",
			settings: Settings{
				Driver: DriverMemory,
			},
			wantErr: false,
		},
		{
			name: "noop driver",
			settings: Settings{
				Driver: DriverNoop,
			},
			wantErr: false,
		},
		{
			name: "unsupported driver",
			settings: Settings{
				Driver: "unsupported",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			msg, err := NewMessenger(tt.settings)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewMessenger() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && msg == nil {
				t.Error("NewMessenger() returned nil messenger")
			}
			if msg != nil {
				msg.Close()
			}
		})
	}
}

func TestMemoryMessenger(t *testing.T) {
	t.Parallel()
	settings := Settings{Driver: DriverMemory}
	msg, err := NewMessenger(settings)
	if err != nil {
		t.Fatal(err)
	}
	defer msg.Close()

	// Test Send
	message := &Message{
		Body:    []byte("test message"),
		Channel: "test-channel",
		Params:  map[string]string{"key": "value"},
	}

	err = msg.Send(context.Background(), "test-topic", message)
	if err != nil {
		t.Errorf("Send() error = %v", err)
	}

	// Test Subscribe
	received := make(chan *Message, 1)
	err = msg.Subscribe(context.Background(), "test-topic", func(ctx context.Context, m *Message) error {
		received <- m
		return nil
	})
	if err != nil {
		t.Errorf("Subscribe() error = %v", err)
	}

	// Send another message to trigger the callback
	err = msg.Send(context.Background(), "test-topic", message)
	if err != nil {
		t.Errorf("Send() error = %v", err)
	}

	// Wait for message to be received
	select {
	case receivedMsg := <-received:
		if string(receivedMsg.Body) != "test message" {
			t.Errorf("Expected 'test message', got %s", string(receivedMsg.Body))
		}
	case <-time.After(5 * time.Second):
		t.Error("Timeout waiting for message")
	}

	// Test Unsubscribe
	err = msg.Unsubscribe(context.Background(), "test-topic")
	if err != nil {
		t.Errorf("Unsubscribe() error = %v", err)
	}
}

func TestNoopMessenger(t *testing.T) {
	t.Parallel()
	settings := Settings{Driver: DriverNoop}
	msg, err := NewMessenger(settings)
	if err != nil {
		t.Fatal(err)
	}
	defer msg.Close()

	// Test Send (should succeed but not actually send)
	message := &Message{
		Body:    []byte("test message"),
		Channel: "test-channel",
	}

	err = msg.Send(context.Background(), "test-topic", message)
	if err != nil {
		t.Errorf("Send() error = %v", err)
	}

	// Test Subscribe (should succeed but not actually subscribe)
	err = msg.Subscribe(context.Background(), "test-topic", func(ctx context.Context, m *Message) error {
		return nil
	})
	if err != nil {
		t.Errorf("Subscribe() error = %v", err)
	}

	// Test Unsubscribe
	err = msg.Unsubscribe(context.Background(), "test-topic")
	if err != nil {
		t.Errorf("Unsubscribe() error = %v", err)
	}
}
