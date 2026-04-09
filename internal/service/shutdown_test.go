package service

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/app/billing"
)

// mockMetricsWriter captures written metrics for assertion.
type mockMetricsWriter struct {
	mu       sync.Mutex
	written  []billing.UsageMetric
	closed   bool
	writeErr error
}

func (m *mockMetricsWriter) Write(ctx context.Context, metrics []billing.UsageMetric) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.written = append(m.written, metrics...)
	return m.writeErr
}

func (m *mockMetricsWriter) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockMetricsWriter) getWritten() []billing.UsageMetric {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]billing.UsageMetric, len(m.written))
	copy(result, m.written)
	return result
}

func (m *mockMetricsWriter) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// TestBillingMeter_FlushesOnStop verifies that the billing meter flushes
// accumulated metrics when Stop is called, simulating what happens during
// graceful shutdown.
func TestBillingMeter_FlushesOnStop(t *testing.T) {
	writer := &mockMetricsWriter{}
	meter := billing.NewMeter(writer, 1*time.Hour) // Long interval so periodic flush does not fire.

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	meter.Start(ctx)

	// Record some usage.
	meter.Record(&billing.UsageMetric{
		WorkspaceID:    "ws-1",
		OriginID:       "origin-1",
		OriginHostname: "example.com",
		RequestCount:   10,
		BytesIn:        1024,
		BytesOut:       2048,
		Period:         time.Now(),
	})

	meter.Record(&billing.UsageMetric{
		WorkspaceID:    "ws-2",
		OriginID:       "origin-2",
		OriginHostname: "other.com",
		RequestCount:   5,
		BytesIn:        512,
		BytesOut:       1024,
		Period:         time.Now(),
	})

	// Stop the meter (simulates shutdown phase 2).
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()

	if err := meter.Stop(stopCtx); err != nil {
		t.Fatalf("meter.Stop failed: %v", err)
	}

	// Verify metrics were flushed.
	written := writer.getWritten()
	if len(written) == 0 {
		t.Fatal("expected metrics to be flushed on Stop, but none were written")
	}

	// Both workspaces should be present.
	wsFound := make(map[string]bool)
	for _, m := range written {
		wsFound[m.WorkspaceID] = true
	}
	if !wsFound["ws-1"] || !wsFound["ws-2"] {
		t.Errorf("expected both ws-1 and ws-2 to be flushed, got: %v", wsFound)
	}

	// Verify writer was closed.
	if !writer.isClosed() {
		t.Error("expected writer to be closed after Stop")
	}
}

// TestBillingMeter_FlushesOnContextCancel verifies that cancelling the Start
// context triggers a final flush of accumulated metrics.
func TestBillingMeter_FlushesOnContextCancel(t *testing.T) {
	writer := &mockMetricsWriter{}
	meter := billing.NewMeter(writer, 1*time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	meter.Start(ctx)

	// Record a metric.
	meter.Record(&billing.UsageMetric{
		WorkspaceID:    "ws-cancel",
		OriginID:       "origin-cancel",
		OriginHostname: "cancel.test",
		RequestCount:   3,
		Period:         time.Now(),
	})

	// Cancel the context (simulates service context cancellation).
	cancel()

	// Give the goroutine time to perform the final flush.
	time.Sleep(500 * time.Millisecond)

	written := writer.getWritten()
	if len(written) == 0 {
		t.Fatal("expected metrics to be flushed on context cancel, but none were written")
	}

	found := false
	for _, m := range written {
		if m.WorkspaceID == "ws-cancel" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected ws-cancel metric to be flushed")
	}
}

// TestGracefulShutdown_CompletesWithinDeadline tests that the health manager's
// shutdown flow works within a reasonable time bound using the building blocks
// exercised by the real shutdown code.
func TestGracefulShutdown_CompletesWithinDeadline(t *testing.T) {
	writer := &mockMetricsWriter{}
	meter := billing.NewMeter(writer, 1*time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	meter.Start(ctx)

	meter.Record(&billing.UsageMetric{
		WorkspaceID:  "ws-shutdown",
		OriginID:     "origin-shutdown",
		RequestCount: 1,
		Period:       time.Now(),
	})

	// Simulate shutdown with a 10-second deadline.
	shutdownStart := time.Now()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	cancel() // Cancel service context first (like phase 3).

	// Stop meter with shutdown context (like phase 2).
	if err := meter.Stop(shutdownCtx); err != nil {
		t.Fatalf("meter.Stop failed during shutdown: %v", err)
	}

	elapsed := time.Since(shutdownStart)
	if elapsed > 10*time.Second {
		t.Errorf("shutdown took %v, expected under 10s", elapsed)
	}

	written := writer.getWritten()
	if len(written) == 0 {
		t.Error("expected at least one metric to be flushed during shutdown")
	}
}

// TestRapidShutdowns_NoGoroutineLeak verifies that 10 rapid start/stop cycles
// of the billing meter do not leak goroutines or timers. The goroutine count
// after all cycles should return to (approximately) the baseline.
func TestRapidShutdowns_NoGoroutineLeak(t *testing.T) {
	// Let any background goroutines from previous tests settle.
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	for i := 0; i < 10; i++ {
		writer := &mockMetricsWriter{}
		meter := billing.NewMeter(writer, 50*time.Millisecond)

		ctx, cancel := context.WithCancel(context.Background())
		meter.Start(ctx)

		// Record a metric so the meter has work to flush.
		meter.Record(&billing.UsageMetric{
			WorkspaceID:  "ws-leak-test",
			OriginID:     "origin-leak",
			RequestCount: 1,
			Period:       time.Now(),
		})

		// Immediately stop.
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
		cancel()
		_ = meter.Stop(stopCtx)
		stopCancel()
	}

	// Let goroutines wind down.
	runtime.GC()
	time.Sleep(500 * time.Millisecond)

	after := runtime.NumGoroutine()
	// Allow a small margin (5) for runtime/test framework goroutines.
	if after > baseline+5 {
		t.Errorf("goroutine leak detected: baseline=%d, after 10 rapid shutdowns=%d (delta=%d)",
			baseline, after, after-baseline)
	}
	t.Logf("goroutine count: baseline=%d, after=%d", baseline, after)
}
