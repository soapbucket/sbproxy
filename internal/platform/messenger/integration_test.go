package messenger

import (
	"context"
	"testing"
)

func TestGCPMessenger_InvalidConfig(t *testing.T) {
	t.Parallel()
	// Test with missing project_id
	settings := Settings{
		Driver: DriverGCP,
		Params: map[string]string{},
	}

	_, err := NewMessenger(settings)
	if err == nil {
		t.Error("Expected error for missing project_id, got nil")
	}
}

func TestAWSMessenger_ValidConfig(t *testing.T) {
	t.Parallel()
	// Test with valid AWS config (should work even without credentials)
	settings := Settings{
		Driver: DriverAWS,
		Params: map[string]string{
			ParamRegion: "us-east-1",
		},
	}

	msg, err := NewMessenger(settings)
	if err != nil {
		t.Logf("AWS messenger creation failed (expected without credentials): %v", err)
		return
	}
	defer msg.Close()

	// Test basic operations (they may fail due to missing credentials, but shouldn't panic)
	message := &Message{
		Body:    []byte("test"),
		Channel: "test",
	}

	// These operations may fail due to missing AWS credentials, but shouldn't panic
	_ = msg.Send(context.Background(), "test-topic", message)
	_ = msg.Subscribe(context.Background(), "test-topic", func(ctx context.Context, m *Message) error {
		return nil
	})
	_ = msg.Unsubscribe(context.Background(), "test-topic")
}

func TestRedisMessenger_InvalidDSN(t *testing.T) {
	t.Parallel()
	// Test with invalid Redis DSN
	settings := Settings{
		Driver: DriverRedis,
		Params: map[string]string{
			"dsn": "invalid://dsn",
		},
	}

	_, err := NewMessenger(settings)
	if err == nil {
		t.Error("Expected error for invalid Redis DSN, got nil")
	}
}
