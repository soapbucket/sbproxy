// Package subscribers contains event subscribers that react to system events for logging, metrics, and side effects.
package subscribers

import (
	"context"
	"log/slog"
	"sync"

	"github.com/soapbucket/sbproxy/internal/observe/events"
)

// LoggerExporter subscribes to events and logs them
type LoggerExporter struct {
	mu sync.Mutex
}

// NewLoggerExporter creates and registers a new logger exporter
func NewLoggerExporter() *LoggerExporter {
	exporter := &LoggerExporter{}

	// Subscribe to all event types we want to log
	events.Subscribe(events.EventCircuitBreakerStateChange, exporter.handleEvent)
	events.Subscribe(events.EventCircuitBreakerOpen, exporter.handleEvent)
	events.Subscribe(events.EventCircuitBreakerClosed, exporter.handleEvent)
	events.Subscribe(events.EventClickHouseDown, exporter.handleEvent)
	events.Subscribe(events.EventClickHouseFlushError, exporter.handleEvent)
	events.Subscribe(events.EventBufferOverflow, exporter.handleEvent)
	events.Subscribe(events.EventBufferSpilledToDisk, exporter.handleEvent)
	events.Subscribe(events.EventConfigServedStale, exporter.handleEvent)

	return exporter
}

// handleEvent logs events based on severity
func (e *LoggerExporter) handleEvent(event events.SystemEvent) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Map severity to log level
	level := slog.LevelInfo
	switch event.Severity {
	case events.SeverityCritical:
		level = slog.LevelError
	case events.SeverityError:
		level = slog.LevelError
	case events.SeverityWarning:
		level = slog.LevelWarn
	case events.SeverityInfo:
		level = slog.LevelInfo
	}

	// Log with context
	slog.Log(context.TODO(), level,
		"system event",
		slog.String("type", string(event.Type)),
		slog.String("source", event.Source),
		slog.String("severity", event.Severity),
		slog.Any("data", event.Data),
	)

	return nil
}
