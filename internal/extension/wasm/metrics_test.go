package wasm

import (
	"fmt"
	"testing"
	"time"
)

func TestPluginMetrics_RecordExecution(t *testing.T) {
	m := &PluginMetrics{}

	m.RecordExecution(10*time.Millisecond, nil)
	if m.TotalCalls.Load() != 1 {
		t.Errorf("TotalCalls = %d, want 1", m.TotalCalls.Load())
	}
	if m.TotalErrors.Load() != 0 {
		t.Errorf("TotalErrors = %d, want 0", m.TotalErrors.Load())
	}

	m.RecordExecution(20*time.Millisecond, fmt.Errorf("test error"))
	if m.TotalCalls.Load() != 2 {
		t.Errorf("TotalCalls = %d, want 2", m.TotalCalls.Load())
	}
	if m.TotalErrors.Load() != 1 {
		t.Errorf("TotalErrors = %d, want 1", m.TotalErrors.Load())
	}

	if m.LastExecTime.Load() == 0 {
		t.Error("LastExecTime should be set")
	}
}

func TestPluginMetrics_AverageLatency(t *testing.T) {
	m := &PluginMetrics{}

	if m.AverageLatency() != 0 {
		t.Errorf("AverageLatency with no calls = %v, want 0", m.AverageLatency())
	}

	m.RecordExecution(10*time.Millisecond, nil)
	m.RecordExecution(30*time.Millisecond, nil)

	avg := m.AverageLatency()
	if avg != 20*time.Millisecond {
		t.Errorf("AverageLatency = %v, want 20ms", avg)
	}
}

func TestPluginMetrics_ErrorRate(t *testing.T) {
	m := &PluginMetrics{}

	if m.ErrorRate() != 0 {
		t.Errorf("ErrorRate with no calls = %v, want 0", m.ErrorRate())
	}

	m.RecordExecution(10*time.Millisecond, nil)
	m.RecordExecution(10*time.Millisecond, fmt.Errorf("err"))
	m.RecordExecution(10*time.Millisecond, nil)
	m.RecordExecution(10*time.Millisecond, fmt.Errorf("err"))

	rate := m.ErrorRate()
	if rate != 0.5 {
		t.Errorf("ErrorRate = %v, want 0.5", rate)
	}
}

func TestMetricsRegistry_Get(t *testing.T) {
	r := NewMetricsRegistry()

	m1 := r.Get("plugin-a")
	if m1 == nil {
		t.Fatal("Get should return non-nil metrics")
	}

	m2 := r.Get("plugin-a")
	if m1 != m2 {
		t.Error("Get should return the same metrics instance for the same plugin")
	}

	m3 := r.Get("plugin-b")
	if m1 == m3 {
		t.Error("Get should return different metrics for different plugins")
	}
}

func TestMetricsRegistry_All(t *testing.T) {
	r := NewMetricsRegistry()

	r.Get("plugin-a")
	r.Get("plugin-b")

	all := r.All()
	if len(all) != 2 {
		t.Errorf("All() returned %d entries, want 2", len(all))
	}

	if _, ok := all["plugin-a"]; !ok {
		t.Error("All() missing plugin-a")
	}
	if _, ok := all["plugin-b"]; !ok {
		t.Error("All() missing plugin-b")
	}
}

func BenchmarkPluginMetrics_RecordExecution(b *testing.B) {
	b.ReportAllocs()
	m := &PluginMetrics{}
	for b.Loop() {
		m.RecordExecution(10*time.Millisecond, nil)
	}
}

func BenchmarkMetricsRegistry_Get(b *testing.B) {
	b.ReportAllocs()
	r := NewMetricsRegistry()
	r.Get("test-plugin") // Pre-create
	for b.Loop() {
		_ = r.Get("test-plugin")
	}
}
