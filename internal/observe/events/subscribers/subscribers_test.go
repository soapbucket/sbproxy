package subscribers

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/events"
)

func TestNewLoggerExporter_Creation(t *testing.T) {
	// Use a dedicated bus so subscriptions don't leak into the global bus.
	bus := events.NewInProcessEventBus(100)
	orig := events.GetBus()
	events.SetBus(bus)
	defer func() {
		bus.Close()
		events.SetBus(orig)
	}()

	exporter := NewLoggerExporter()
	if exporter == nil {
		t.Fatal("expected non-nil LoggerExporter")
	}
}

func TestNewPrometheusExporter_Creation(t *testing.T) {
	bus := events.NewInProcessEventBus(100)
	orig := events.GetBus()
	events.SetBus(bus)
	defer func() {
		bus.Close()
		events.SetBus(orig)
	}()

	exporter := NewPrometheusExporter()
	if exporter == nil {
		t.Fatal("expected non-nil PrometheusExporter")
	}
}

func TestLoggerExporter_EventFiltering(t *testing.T) {
	bus := events.NewInProcessEventBus(100)
	orig := events.GetBus()
	events.SetBus(bus)
	defer func() {
		bus.Close()
		events.SetBus(orig)
	}()

	exporter := NewLoggerExporter()
	if exporter == nil {
		t.Fatal("expected non-nil LoggerExporter")
	}

	// The logger subscribes to specific event types. Publishing a subscribed
	// event type should not cause any error (the handler just logs).
	err := events.Publish(events.SystemEvent{
		Type:     events.EventCircuitBreakerOpen,
		Severity: events.SeverityCritical,
		Source:   "test",
		Data:     map[string]interface{}{"service": "backend"},
	})
	if err != nil {
		t.Fatalf("publish failed: %v", err)
	}
}

func TestLoggerExporter_HandleEvent_Severities(t *testing.T) {
	exporter := &LoggerExporter{}

	severities := []string{
		events.SeverityCritical,
		events.SeverityError,
		events.SeverityWarning,
		events.SeverityInfo,
	}

	for _, sev := range severities {
		t.Run(sev, func(t *testing.T) {
			err := exporter.handleEvent(events.SystemEvent{
				Type:     events.EventCircuitBreakerStateChange,
				Severity: sev,
				Source:   "test",
				Data:     map[string]interface{}{"info": "test data"},
			})
			if err != nil {
				t.Errorf("handleEvent returned error for severity %s: %v", sev, err)
			}
		})
	}
}

func TestPrometheusExporter_EventDelivery(t *testing.T) {
	bus := events.NewInProcessEventBus(100)
	orig := events.GetBus()
	events.SetBus(bus)
	defer func() {
		bus.Close()
		events.SetBus(orig)
	}()

	_ = NewPrometheusExporter()

	// Publish a circuit breaker state change event
	err := events.Publish(events.SystemEvent{
		Type:     events.EventCircuitBreakerStateChange,
		Severity: events.SeverityWarning,
		Source:   "test",
		Data: map[string]interface{}{
			"service":   "api-backend",
			"old_state": "closed",
			"new_state": "open",
		},
	})
	if err != nil {
		t.Fatalf("publish failed: %v", err)
	}

	// Give async dispatch time to process
	time.Sleep(50 * time.Millisecond)
}

func TestPrometheusExporter_CircuitBreakerOpen(t *testing.T) {
	exporter := &PrometheusExporter{}
	err := exporter.handleCircuitBreakerOpen(events.SystemEvent{
		Type:     events.EventCircuitBreakerOpen,
		Severity: events.SeverityCritical,
		Source:   "test",
		Data:     map[string]interface{}{"service": "upstream"},
	})
	if err != nil {
		t.Fatalf("handleCircuitBreakerOpen returned error: %v", err)
	}
}

func TestPrometheusExporter_CircuitBreakerClosed(t *testing.T) {
	exporter := &PrometheusExporter{}
	err := exporter.handleCircuitBreakerClosed(events.SystemEvent{
		Type:     events.EventCircuitBreakerClosed,
		Severity: events.SeverityInfo,
		Source:   "test",
		Data:     map[string]interface{}{"service": "upstream"},
	})
	if err != nil {
		t.Fatalf("handleCircuitBreakerClosed returned error: %v", err)
	}
}

func TestPrometheusExporter_CircuitBreakerStateChange_MissingService(t *testing.T) {
	exporter := &PrometheusExporter{}
	// When service key is missing from Data, the handler should return nil (no-op).
	err := exporter.handleCircuitBreakerStateChange(events.SystemEvent{
		Type: events.EventCircuitBreakerStateChange,
		Data: map[string]interface{}{},
	})
	if err != nil {
		t.Fatalf("expected nil, got error: %v", err)
	}
}

func TestPrometheusExporter_BufferOverflow(t *testing.T) {
	exporter := &PrometheusExporter{}

	// With buffer_type
	err := exporter.handleBufferOverflow(events.SystemEvent{
		Type: events.EventBufferOverflow,
		Data: map[string]interface{}{"buffer_type": "analytics"},
	})
	if err != nil {
		t.Fatalf("handleBufferOverflow returned error: %v", err)
	}

	// Without buffer_type (defaults to "unknown")
	err = exporter.handleBufferOverflow(events.SystemEvent{
		Type: events.EventBufferOverflow,
		Data: map[string]interface{}{},
	})
	if err != nil {
		t.Fatalf("handleBufferOverflow returned error: %v", err)
	}
}

func TestPrometheusExporter_ClickHouseEvents(t *testing.T) {
	exporter := &PrometheusExporter{}

	err := exporter.handleClickHouseSuccess(events.SystemEvent{
		Type: events.EventClickHouseFlushSuccess,
	})
	if err != nil {
		t.Fatalf("handleClickHouseSuccess returned error: %v", err)
	}

	err = exporter.handleClickHouseError(events.SystemEvent{
		Type: events.EventClickHouseFlushError,
	})
	if err != nil {
		t.Fatalf("handleClickHouseError returned error: %v", err)
	}
}

func TestLoggerExporter_ConcurrentHandling(t *testing.T) {
	exporter := &LoggerExporter{}
	var wg sync.WaitGroup
	var errCount atomic.Int32

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := exporter.handleEvent(events.SystemEvent{
				Type:     events.EventConfigUpdated,
				Severity: events.SeverityInfo,
				Source:   "test",
				Data:     map[string]interface{}{"key": "value"},
			})
			if err != nil {
				errCount.Add(1)
			}
		}()
	}
	wg.Wait()

	if errCount.Load() != 0 {
		t.Errorf("expected 0 errors, got %d", errCount.Load())
	}
}

func TestPrometheusExporter_CircuitBreakerStateChange_AllStates(t *testing.T) {
	exporter := &PrometheusExporter{}

	tests := []struct {
		name     string
		newState string
	}{
		{"open", "open"},
		{"half_open", "half_open"},
		{"closed", "closed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := exporter.handleCircuitBreakerStateChange(events.SystemEvent{
				Type: events.EventCircuitBreakerStateChange,
				Data: map[string]interface{}{
					"service":   "test-svc",
					"old_state": "closed",
					"new_state": tt.newState,
				},
			})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
