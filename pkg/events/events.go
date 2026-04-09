// Package events provides a publish/subscribe event bus for proxy lifecycle events.
//
// The package uses a dual-bus architecture with a global singleton. A no-op bus
// is used by default, making all Publish calls free. Call [SetBus] at startup to
// install a real implementation backed by Redis Streams, an in-memory dispatcher,
// or another transport.
//
// This design means any package can safely call [Publish] without checking whether
// an event bus is configured. Events are fire-and-forget from the caller's perspective.
package events

import "context"

// EventBus is the public interface for event publishing and subscription. The proxy
// engine and plugins interact with the bus through this interface, never with a
// concrete implementation directly.
type EventBus interface {
	// Publish sends an event to all subscribers of the event's type. Implementations
	// should be non-blocking or use bounded internal queues to avoid slowing down
	// request processing. The context carries request-scoped values like trace IDs.
	Publish(ctx context.Context, event Event) error

	// Subscribe registers a handler function that will be called for every event
	// of the given type. Handlers run asynchronously and must be safe for concurrent
	// invocation. The eventType string should match the value returned by Event.EventType().
	Subscribe(eventType string, handler func(Event) error)

	// Close shuts down the event bus, flushing any buffered events and releasing
	// resources. After Close returns, further Publish calls are silently discarded.
	Close() error
}

// Event is the base interface that all proxy events must implement. Concrete event
// types (request events, policy events, error events) embed [EventBase] to satisfy
// this interface automatically.
type Event interface {
	// EventType returns the dot-separated event type string (e.g., "request.completed",
	// "policy.rate_limit.triggered").
	EventType() string

	// EventSeverity returns the severity level of this event. See the Severity
	// constants in types.go.
	EventSeverity() string
}

// globalBus is the default when no bus is configured.
var globalBus EventBus = &noopBus{}

// SetBus replaces the global event bus. Call this once during startup, before the
// proxy begins serving requests, to install a real event bus implementation.
// Passing nil is not allowed and will cause panics on Publish.
func SetBus(bus EventBus) { globalBus = bus }

// GetBus returns the current global event bus. Use this when you need to call
// Subscribe or Close. For publishing, prefer the package-level [Publish] function.
func GetBus() EventBus { return globalBus }

// Publish sends an event on the global event bus. This is always safe to call,
// even if no bus has been configured (in which case it is a no-op). Returns nil
// when no bus is configured.
func Publish(ctx context.Context, event Event) error {
	return globalBus.Publish(ctx, event)
}

type noopBus struct{}

func (n *noopBus) Publish(context.Context, Event) error { return nil }
func (n *noopBus) Subscribe(string, func(Event) error)  {}
func (n *noopBus) Close() error                         { return nil }
