# SBproxy Events Guide

*Last modified: 2026-04-12*

SBproxy includes a publish-subscribe event system for observability and inter-component communication. Internal components emit events when notable things happen (circuit breakers tripping, configs updating, buffers overflowing), and you can subscribe handlers to react to them.

## Event Types

The following event types are built in:

### Circuit Breaker Events

| Event | Severity | When |
|-------|----------|------|
| `circuit_breaker_state_change` | warning | Circuit breaker transitions between states |
| `circuit_breaker_open` | critical | Circuit breaker opens (backend marked unhealthy) |
| `circuit_breaker_closed` | info | Circuit breaker closes (backend recovered) |
| `circuit_breaker_half_open` | info | Circuit breaker enters half-open probe state |

### Analytics Events

| Event | Severity | When |
|-------|----------|------|
| `clickhouse_down` | critical | ClickHouse analytics writer is unavailable |
| `clickhouse_up` | info | ClickHouse analytics writer recovered |
| `clickhouse_flush_success` | info | Analytics batch flushed successfully |
| `clickhouse_flush_error` | error | Analytics batch flush failed |
| `clickhouse_max_retries_exceeded` | critical | Analytics flush retries exhausted |

### Buffer Events

| Event | Severity | When |
|-------|----------|------|
| `buffer_overflow` | warning | Internal buffer is full, events may be dropped |
| `buffer_spilled_to_disk` | warning | Buffer exceeded memory limit, spilling to disk |

### Config Events

| Event | Severity | When |
|-------|----------|------|
| `config_served_stale` | warning | Serving a stale config because refresh failed |
| `config_updated` | info | Configuration was reloaded successfully |

### Security Events

| Event | Severity | When |
|-------|----------|------|
| `https_proxy_auth_failed` | warning | HTTPS proxy authentication attempt failed |

## Event Structure

Every event carries these fields:

```go
type SystemEvent struct {
    Type        EventType              // e.g., "circuit_breaker_open"
    Severity    string                 // "critical", "error", "warning", "info"
    Timestamp   time.Time              // When the event occurred (UTC)
    Source      string                 // Component that emitted it
    Data        map[string]interface{} // Event-specific payload
    Tags        map[string]string      // Optional key-value metadata
    WorkspaceID string                 // Tenant isolation (empty = system-wide)
}
```

Severity levels from highest to lowest: `critical`, `error`, `warning`, `info`.

## Subscribing to Events

### Basic subscriber

Register a handler for a specific event type:

```go
import "github.com/soapbucket/sbproxy/internal/observe/events"

events.Subscribe(events.EventCircuitBreakerOpen, func(event events.SystemEvent) error {
    log.Printf("Circuit breaker opened for %s: %v", event.Source, event.Data)
    return nil
})
```

### Subscribe to multiple event types

```go
alertTypes := []events.EventType{
    events.EventCircuitBreakerOpen,
    events.EventBufferOverflow,
}

handler := func(event events.SystemEvent) error {
    sendAlert(event.Type, event.Severity, event.Data)
    return nil
}

for _, t := range alertTypes {
    events.Subscribe(t, handler)
}
```

### Unsubscribe

Remove a handler when it is no longer needed:

```go
events.GetBus().Unsubscribe(events.EventCircuitBreakerOpen, myHandler)
```

## Publishing Events

Components publish events through the global bus:

```go
import "github.com/soapbucket/sbproxy/internal/observe/events"

events.Publish(events.SystemEvent{
    Type:     events.EventConfigUpdated,
    Severity: events.SeverityInfo,
    Source:   "config_loader",
    Data: map[string]interface{}{
        "origins_count": 12,
        "reload_time_ms": 45,
    },
    Tags: map[string]string{
        "trigger": "file_watch",
    },
})
```

The `Timestamp` field is auto-populated if left as the zero value.

## Public API (pkg/events)

For external consumers building plugins or integrations, sbproxy exposes a simplified event interface in the `pkg/events` package:

```go
import "github.com/soapbucket/sbproxy/pkg/events"

// The public interface
type EventBus interface {
    Publish(ctx context.Context, event Event) error
    Subscribe(eventType string, handler func(Event) error)
    Close() error
}

// Get or replace the global bus
bus := events.GetBus()
events.SetBus(myCustomBus)

// Publish via the global bus
events.Publish(ctx, myEvent)
```

The public `Event` interface requires two methods:

```go
type Event interface {
    EventType() string
    EventSeverity() string
}
```

Use the `EventBase` struct for convenience:

```go
event := &events.EventBase{
    Type:      "my_custom_event",
    Severity:  events.SeverityInfo,
    Timestamp: time.Now().UTC(),
    RequestID: "req-123",
    Origin: events.OriginContext{
        OriginID:    "origin-456",
        Hostname:    "api.example.com",
        WorkspaceID: "ws-789",
    },
}
```

## Architecture

The default event bus is an in-process implementation backed by a buffered channel (default size: 1,000 events). Four worker goroutines read from the channel and dispatch events to registered handlers.

Key characteristics:

- **Non-blocking publish**: If the buffer is full, the event is dropped and a metric is recorded. Publishing never blocks the caller.
- **Concurrent dispatch**: Handlers run in separate goroutines with a global concurrency limit of 32 in-flight handlers.
- **Workspace isolation**: Events with a `WorkspaceID` are dispatched through per-workspace semaphores, preventing one tenant's handler backlog from affecting others.
- **Graceful shutdown**: Calling `Close()` signals workers to drain buffered events and waits for all in-flight handlers to finish.
- **Timeout monitoring**: Handlers that exceed 30 seconds are logged but not killed, avoiding partial state.

## Patterns

### Metrics bridge

Forward events to your metrics system:

```go
events.Subscribe(events.EventCircuitBreakerStateChange, func(event events.SystemEvent) error {
    state, _ := event.Data["new_state"].(string)
    backend, _ := event.Data["backend"].(string)
    prometheus.CircuitBreakerState.WithLabelValues(backend).Set(stateToFloat(state))
    return nil
})
```

### Audit logging

Log all config changes for compliance:

```go
events.Subscribe(events.EventConfigUpdated, func(event events.SystemEvent) error {
    auditLog.Info("config reloaded",
        "workspace", event.WorkspaceID,
        "source", event.Source,
        "origins_count", event.Data["origins_count"],
    )
    return nil
})
```

### Workspace-scoped handlers

Events with a `WorkspaceID` are isolated per tenant. You can filter in your handler:

```go
events.Subscribe(events.EventCircuitBreakerOpen, func(event events.SystemEvent) error {
    if event.WorkspaceID == "" {
        // System-wide event
        return notifyOps(event)
    }
    // Tenant-specific event
    return notifyTenant(event.WorkspaceID, event)
})
```

## Lifecycle

The global event bus is initialized at startup. To shut it down cleanly during application exit:

```go
if err := events.CloseGlobalBus(); err != nil {
    log.Printf("error closing event bus: %v", err)
}
```

This drains any remaining buffered events and waits for in-flight handlers to complete before returning.
