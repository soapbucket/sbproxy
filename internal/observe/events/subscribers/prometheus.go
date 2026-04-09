// Package subscribers contains event subscribers that react to system events for logging, metrics, and side effects.
package subscribers

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/soapbucket/sbproxy/internal/observe/events"
)

var (
	// Circuit breaker metrics
	circuitBreakerStateChanges = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sb_circuit_breaker_state_changes_total",
			Help: "Total circuit breaker state transitions",
		},
		[]string{"service", "old_state", "new_state"},
	)

	circuitBreakerState = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sb_circuit_breaker_state",
			Help: "Current circuit breaker state (0=closed, 1=open, 2=half_open)",
		},
		[]string{"service"},
	)

	// ClickHouse metrics
	clickhouseFlushSuccesses = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sb_clickhouse_flush_successes_total",
			Help: "Successful ClickHouse flush operations",
		},
		[]string{},
	)

	clickhouseFlushFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sb_clickhouse_flush_failures_total",
			Help: "Failed ClickHouse flush operations",
		},
		[]string{},
	)

	// Buffer metrics
	bufferOverflows = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sb_buffer_overflow_total",
			Help: "Times buffer overflowed to disk",
		},
		[]string{"buffer_type"},
	)
)

// PrometheusExporter subscribes to events and exports them as Prometheus metrics
type PrometheusExporter struct{}

// NewPrometheusExporter creates and registers a new Prometheus exporter
func NewPrometheusExporter() *PrometheusExporter {
	exporter := &PrometheusExporter{}

	// Subscribe to relevant events
	events.Subscribe(events.EventCircuitBreakerStateChange, exporter.handleCircuitBreakerStateChange)
	events.Subscribe(events.EventCircuitBreakerOpen, exporter.handleCircuitBreakerOpen)
	events.Subscribe(events.EventCircuitBreakerClosed, exporter.handleCircuitBreakerClosed)
	events.Subscribe(events.EventClickHouseFlushSuccess, exporter.handleClickHouseSuccess)
	events.Subscribe(events.EventClickHouseFlushError, exporter.handleClickHouseError)
	events.Subscribe(events.EventBufferOverflow, exporter.handleBufferOverflow)

	return exporter
}

// handleCircuitBreakerStateChange processes state change events
func (e *PrometheusExporter) handleCircuitBreakerStateChange(event events.SystemEvent) error {
	service, ok := event.Data["service"].(string)
	if !ok {
		return nil
	}

	oldState, _ := event.Data["old_state"].(string)
	newState, _ := event.Data["new_state"].(string)

	circuitBreakerStateChanges.WithLabelValues(service, oldState, newState).Inc()

	// Update state gauge
	stateValue := 0.0
	if newState == "open" {
		stateValue = 1.0
	} else if newState == "half_open" {
		stateValue = 2.0
	}
	circuitBreakerState.WithLabelValues(service).Set(stateValue)

	return nil
}

// handleCircuitBreakerOpen processes open events
func (e *PrometheusExporter) handleCircuitBreakerOpen(event events.SystemEvent) error {
	service, ok := event.Data["service"].(string)
	if !ok {
		return nil
	}

	circuitBreakerState.WithLabelValues(service).Set(1.0)
	return nil
}

// handleCircuitBreakerClosed processes closed events
func (e *PrometheusExporter) handleCircuitBreakerClosed(event events.SystemEvent) error {
	service, ok := event.Data["service"].(string)
	if !ok {
		return nil
	}

	circuitBreakerState.WithLabelValues(service).Set(0.0)
	return nil
}

// handleClickHouseSuccess processes successful flush events
func (e *PrometheusExporter) handleClickHouseSuccess(event events.SystemEvent) error {
	clickhouseFlushSuccesses.WithLabelValues().Inc()
	return nil
}

// handleClickHouseError processes failed flush events
func (e *PrometheusExporter) handleClickHouseError(event events.SystemEvent) error {
	clickhouseFlushFailures.WithLabelValues().Inc()
	return nil
}

// handleBufferOverflow processes buffer overflow events
func (e *PrometheusExporter) handleBufferOverflow(event events.SystemEvent) error {
	bufferType, _ := event.Data["buffer_type"].(string)
	if bufferType == "" {
		bufferType = "unknown"
	}

	bufferOverflows.WithLabelValues(bufferType).Inc()
	return nil
}
