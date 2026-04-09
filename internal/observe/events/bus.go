// Package events implements a publish-subscribe event framework for system observability
package events

import (
	"log/slog"
	"reflect"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// EventType defines the type of event
type EventType string

const (
	// Circuit breaker events
	EventCircuitBreakerStateChange EventType = "circuit_breaker_state_change"
	// EventCircuitBreakerOpen is a constant for event circuit breaker open.
	EventCircuitBreakerOpen EventType = "circuit_breaker_open"
	// EventCircuitBreakerClosed is a constant for event circuit breaker closed.
	EventCircuitBreakerClosed EventType = "circuit_breaker_closed"
	// EventCircuitBreakerHalfOpen is a constant for event circuit breaker half open.
	EventCircuitBreakerHalfOpen EventType = "circuit_breaker_half_open"

	// ClickHouse events
	EventClickHouseDown EventType = "clickhouse_down"
	// EventClickHouseUp is a constant for event click house up.
	EventClickHouseUp EventType = "clickhouse_up"
	// EventClickHouseFlushSuccess is a constant for event click house flush success.
	EventClickHouseFlushSuccess EventType = "clickhouse_flush_success"
	// EventClickHouseFlushError is a constant for event click house flush error.
	EventClickHouseFlushError EventType = "clickhouse_flush_error"
	// EventClickHouseMaxRetriesExceeded is a constant for event click house max retries exceeded.
	EventClickHouseMaxRetriesExceeded EventType = "clickhouse_max_retries_exceeded"

	// Buffer events
	EventBufferOverflow EventType = "buffer_overflow"
	// EventBufferSpilledToDisk is a constant for event buffer spilled to disk.
	EventBufferSpilledToDisk EventType = "buffer_spilled_to_disk"

	// Config events
	EventConfigServedStale EventType = "config_served_stale"
	// EventConfigUpdated is a constant for event config updated.
	EventConfigUpdated EventType = "config_updated"

	// HTTPS proxy system events
	EventHTTPSProxyAuthFailed EventType = "https_proxy_auth_failed"
)

// SystemEvent represents a system-wide event with metadata
type SystemEvent struct {
	Type        EventType
	Severity    string
	Timestamp   time.Time
	Source      string // "circuit_breaker", "clickhouse_writer", etc.
	Data        map[string]interface{}
	Tags        map[string]string
	WorkspaceID string // Multi-tenant isolation: empty means system-wide, non-empty means workspace-specific
}

// EventHandler is a callback function that processes events
type EventHandler func(event SystemEvent) error

// EventBus defines the pub-sub interface
type EventBus interface {
	// Publish sends an event to all subscribers (non-blocking)
	Publish(event SystemEvent) error

	// Subscribe registers a handler for events of a specific type
	Subscribe(eventType EventType, handler EventHandler)

	// Unsubscribe removes a handler
	Unsubscribe(eventType EventType, handler EventHandler)

	// Close gracefully shuts down the event bus
	Close() error
}

// InProcessEventBus implements EventBus using in-process channels
type InProcessEventBus struct {
	handlers   map[EventType][]EventHandler
	mu         sync.RWMutex
	buffer     chan SystemEvent
	stopCh     chan struct{}
	wg         sync.WaitGroup
	handlerSem chan struct{}
	// Per-workspace semaphores for tenant isolation
	perWorkspaceSem map[string]chan struct{}
	semMu           sync.RWMutex
	// Worker pool configuration
	workerCount     int
	dispatchTimeout time.Duration
}

// NewInProcessEventBus creates a new in-process event bus with a worker pool.
// workerCount dispatcher goroutines read from a shared buffer channel.
// If bufferSize is 0, it defaults to 1000. If workerCount is 0, it defaults to 4.
func NewInProcessEventBus(bufferSize int) *InProcessEventBus {
	if bufferSize == 0 {
		bufferSize = 1000
	}

	bus := &InProcessEventBus{
		handlers:        make(map[EventType][]EventHandler),
		buffer:          make(chan SystemEvent, bufferSize),
		stopCh:          make(chan struct{}),
		handlerSem:      make(chan struct{}, 32),
		perWorkspaceSem: make(map[string]chan struct{}),
		workerCount:     4,
		dispatchTimeout: 30 * time.Second,
	}

	// Launch N dispatcher goroutines. Go channels handle multiple consumers safely,
	// so each worker reads from the shared buffer channel.
	for i := 0; i < bus.workerCount; i++ {
		bus.wg.Add(1)
		go bus.dispatch(i)
	}

	return bus
}

// Publish sends an event to the bus (non-blocking)
func (b *InProcessEventBus) Publish(event SystemEvent) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	select {
	case b.buffer <- event:
		return nil
	case <-b.stopCh:
		return ErrBusStopped
	default:
		// Buffer full, drop event with warning
		metric.EventBusDropped(string(event.Type))
		slog.Warn("event bus buffer full, dropping event",
			"type", event.Type,
			"source", event.Source)
		return ErrBufferFull
	}
}

// Subscribe registers a handler for a specific event type
func (b *InProcessEventBus) Subscribe(eventType EventType, handler EventHandler) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.handlers[eventType] = append(b.handlers[eventType], handler)
}

// Unsubscribe removes a handler by comparing function pointers via reflect.
// Since Go functions are not directly comparable, we use reflect.ValueOf(handler).Pointer()
// to obtain a comparable function pointer for matching.
func (b *InProcessEventBus) Unsubscribe(eventType EventType, handler EventHandler) {
	b.mu.Lock()
	defer b.mu.Unlock()

	handlers, ok := b.handlers[eventType]
	if !ok {
		return
	}

	targetPtr := reflect.ValueOf(handler).Pointer()
	filtered := handlers[:0]
	for _, h := range handlers {
		if reflect.ValueOf(h).Pointer() != targetPtr {
			filtered = append(filtered, h)
		}
	}
	b.handlers[eventType] = filtered
}

// dispatch processes events in the background. Each worker reads from the shared
// buffer channel. When Close() signals via stopCh, workers drain remaining
// buffered events before exiting.
func (b *InProcessEventBus) dispatch(workerID int) {
	defer b.wg.Done()

	for {
		select {
		case event := <-b.buffer:
			b.dispatchEvent(event)
		case <-b.stopCh:
			// Stop signal received. Drain remaining buffered events before exiting.
			for {
				select {
				case event := <-b.buffer:
					b.dispatchEvent(event)
				default:
					return
				}
			}
		}
	}
}

// dispatchEvent sends event to all registered handlers
func (b *InProcessEventBus) dispatchEvent(event SystemEvent) {
	b.mu.RLock()
	handlers := b.handlers[event.Type]
	// Copy handlers to avoid lock during execution
	handlersCopy := make([]EventHandler, len(handlers))
	copy(handlersCopy, handlers)
	b.mu.RUnlock()

	// Get or create per-workspace semaphore if WorkspaceID is set
	var workspaceSem chan struct{}
	if event.WorkspaceID != "" {
		b.semMu.Lock()
		if _, ok := b.perWorkspaceSem[event.WorkspaceID]; !ok {
			// Lazy-initialize workspace semaphore (same limit as global)
			b.perWorkspaceSem[event.WorkspaceID] = make(chan struct{}, 32)
		}
		workspaceSem = b.perWorkspaceSem[event.WorkspaceID]
		b.semMu.Unlock()
	}

	for _, handler := range handlersCopy {
		select {
		case b.handlerSem <- struct{}{}:
		case <-b.stopCh:
			return
		}

		// If workspace-specific, also acquire workspace semaphore
		if workspaceSem != nil {
			select {
			case workspaceSem <- struct{}{}:
			case <-b.stopCh:
				<-b.handlerSem
				return
			}
		}

		b.wg.Add(1)
		go func(h EventHandler, ws chan struct{}) {
			defer b.wg.Done()
			defer func() { <-b.handlerSem }()
			if ws != nil {
				defer func() { <-ws }()
			}

			// Track handler duration and warn if it exceeds the dispatch timeout.
			// We log but do not kill the handler to avoid partial state.
			start := time.Now()
			done := make(chan struct{})
			go func() {
				defer close(done)
				if err := h(event); err != nil {
					slog.Error("event handler error",
						"type", event.Type,
						"source", event.Source,
						"workspace", event.WorkspaceID,
						"error", err)
				}
			}()

			timer := time.NewTimer(b.dispatchTimeout)
			select {
			case <-done:
				timer.Stop()
			case <-timer.C:
				slog.Warn("event handler exceeded dispatch timeout",
					"type", event.Type,
					"source", event.Source,
					"workspace", event.WorkspaceID,
					"timeout", b.dispatchTimeout,
					"elapsed", time.Since(start))
				// Wait for handler to finish; do not kill it.
				<-done
			}
		}(handler, workspaceSem)
	}
}

// Close gracefully shuts down the bus. It signals workers to stop via stopCh,
// which triggers each worker to drain remaining buffered events before exiting.
// Then it waits for all worker goroutines and in-flight handlers to finish.
// The buffer channel is not closed to avoid panics from concurrent Publish calls.
func (b *InProcessEventBus) Close() error {
	close(b.stopCh)
	b.wg.Wait()
	return nil
}

// Global event bus instance
var globalBus EventBus

// init initializes the global event bus
func init() {
	globalBus = NewInProcessEventBus(1000)
}

// Publish sends an event to the global bus
func Publish(event SystemEvent) error {
	return globalBus.Publish(event)
}

// Subscribe registers a handler with the global bus
func Subscribe(eventType EventType, handler EventHandler) {
	globalBus.Subscribe(eventType, handler)
}

// GetBus returns the global event bus (for testing/configuration)
func GetBus() EventBus {
	return globalBus
}

// SetBus replaces the global event bus (for testing)
func SetBus(bus EventBus) {
	globalBus = bus
}

// CloseGlobalBus gracefully shuts down the global event bus, draining any
// remaining buffered events before returning.
func CloseGlobalBus() error {
	if globalBus != nil {
		return globalBus.Close()
	}
	return nil
}
