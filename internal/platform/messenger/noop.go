// Package messenger provides a pluggable notification system for alerts and event delivery.
package messenger

import (
	"context"
	"log/slog"
)

// NoopMessenger is a variable for noop messenger.
var NoopMessenger Messenger = &noop{}

type noop struct {
	driver string
}

// Send performs the send operation on the noop.
func (n *noop) Send(_ context.Context, topic string, message *Message) error {
	slog.Debug("sending noop message", "topic", topic, "message", message)
	return nil
}

// Subscribe performs the subscribe operation on the noop.
func (n *noop) Subscribe(_ context.Context, topic string, callback func(context.Context, *Message) error) error {
	slog.Debug("subscribing to noop topic", "topic", topic)
	return nil
}

// Unsubscribe performs the unsubscribe operation on the noop.
func (n *noop) Unsubscribe(_ context.Context, topic string) error {
	slog.Debug("unsubscribing from noop topic", "topic", topic)
	return nil
}

// Close releases resources held by the noop.
func (n *noop) Close() error {
	slog.Debug("closing noop messenger")
	return nil
}

// Driver returns the driver name
func (n *noop) Driver() string {
	return n.driver
}

// NewNoopMessenger creates and initializes a new NoopMessenger.
func NewNoopMessenger(settings Settings) (Messenger, error) {
	return &noop{driver: settings.Driver}, nil
}

func init() {
	Register(DriverNoop, NewNoopMessenger)
}
