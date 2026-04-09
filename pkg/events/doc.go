// Package events provides the event bus interface for proxy observability.
//
// Components publish typed events (circuit breaker changes, config updates,
// buffer overflows) through the EventBus interface. Subscribers register
// handlers to react to specific event types. A no-op bus is used when no
// concrete implementation is configured.
package events
