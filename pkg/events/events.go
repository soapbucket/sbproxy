package events

import "context"

// EventBus provides publish/subscribe for proxy events.
type EventBus interface {
	Publish(ctx context.Context, event Event) error
	Subscribe(eventType string, handler func(Event) error)
	Close() error
}

// Event is the base interface for all proxy events.
type Event interface {
	EventType() string
	EventSeverity() string
}

// globalBus is the default when no bus is configured.
var globalBus EventBus = &noopBus{}

// SetBus replaces the global event bus.
func SetBus(bus EventBus) { globalBus = bus }

// GetBus returns the global event bus.
func GetBus() EventBus { return globalBus }

// Publish sends an event on the global bus.
func Publish(ctx context.Context, event Event) error {
	return globalBus.Publish(ctx, event)
}

type noopBus struct{}

func (n *noopBus) Publish(context.Context, Event) error { return nil }
func (n *noopBus) Subscribe(string, func(Event) error)  {}
func (n *noopBus) Close() error                         { return nil }
