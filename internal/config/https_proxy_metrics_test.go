package config

import (
	"testing"
	"time"
)

func TestNewMetricsCollector(t *testing.T) {
	mc := NewMetricsCollector("test")
	if mc == nil {
		t.Fatal("metrics collector is nil")
	}
	if mc.tunnelEstablishedTotal == nil {
		t.Error("tunnel established counter not initialized")
	}
	if mc.activeTunnels == nil {
		t.Error("active tunnels gauge not initialized")
	}
}

func TestNewMetricsCollectorDefaultSubsystem(t *testing.T) {
	mc := NewMetricsCollector("")
	if mc == nil {
		t.Fatal("metrics collector is nil")
	}
}

func TestRecordTunnelEstablished(t *testing.T) {
	mc := NewMetricsCollector("test")
	// Should not panic
	mc.RecordTunnelEstablished()
	mc.RecordTunnelEstablished()
}

func TestRecordTunnelFailed(t *testing.T) {
	mc := NewMetricsCollector("test")
	// Should not panic
	mc.RecordTunnelFailed("connection refused")
}

func TestRecordTunnelClosed(t *testing.T) {
	mc := NewMetricsCollector("test")
	duration := 5 * time.Second
	bytes := int64(10240)
	// Should not panic
	mc.RecordTunnelClosed(duration, bytes)
}

func TestRecordAIProviderDetected(t *testing.T) {
	mc := NewMetricsCollector("test")
	// Should not panic
	mc.RecordAIProviderDetected("openai")
	mc.RecordAIProviderDetected("anthropic")
}

func TestRecordAIProviderBypassed(t *testing.T) {
	mc := NewMetricsCollector("test")
	// Should not panic
	mc.RecordAIProviderBypassed("openai")
}

func TestRecordProviderError(t *testing.T) {
	mc := NewMetricsCollector("test")
	// Should not panic
	mc.RecordProviderError("openai")
}

func TestRecordDataTransfer(t *testing.T) {
	mc := NewMetricsCollector("test")
	// Should not panic
	mc.RecordDataTransfer("openai", 1024, 2048)
	mc.RecordDataTransfer("anthropic", 0, 0) // Zero values
}

func TestRecordRequestLatency(t *testing.T) {
	mc := NewMetricsCollector("test")
	// Should not panic
	mc.RecordRequestLatency("openai", 100*time.Millisecond)
	mc.RecordRequestLatency("anthropic", 1*time.Second)
}

func TestRecordEstimatedCost(t *testing.T) {
	mc := NewMetricsCollector("test")
	// Should not panic
	mc.RecordEstimatedCost("openai", 0.05)
	mc.RecordEstimatedCost("openai", 0.03)
}

func TestGetProviderMetrics(t *testing.T) {
	mc := NewMetricsCollector("test")

	// Record something for a provider
	mc.RecordAIProviderDetected("openai")

	pm := mc.GetProviderMetrics("openai")
	if pm == nil {
		t.Fatal("provider metrics is nil")
	}

	// Non-existent provider
	pm2 := mc.GetProviderMetrics("nonexistent")
	if pm2 != nil {
		t.Error("expected nil for nonexistent provider")
	}
}

func TestGetAllProviderMetrics(t *testing.T) {
	mc := NewMetricsCollector("test")

	// Record for multiple providers
	mc.RecordAIProviderDetected("openai")
	mc.RecordAIProviderDetected("anthropic")
	mc.RecordAIProviderDetected("google")

	all := mc.GetAllProviderMetrics()
	if len(all) < 3 {
		t.Errorf("expected at least 3 providers, got %d", len(all))
	}

	if _, ok := all["openai"]; !ok {
		t.Error("openai not in metrics")
	}
	if _, ok := all["anthropic"]; !ok {
		t.Error("anthropic not in metrics")
	}
}

func TestNewTunnelMetrics(t *testing.T) {
	tm := NewTunnelMetrics("openai", true)
	if tm == nil {
		t.Fatal("tunnel metrics is nil")
	}
	if tm.Provider != "openai" {
		t.Errorf("provider = %s, expected openai", tm.Provider)
	}
	if !tm.IsAIProvider {
		t.Error("IsAIProvider should be true")
	}
	if tm.BytesTransferred != 0 {
		t.Error("initial bytes should be 0")
	}
}

func TestTunnelMetricsAddBytes(t *testing.T) {
	tm := NewTunnelMetrics("openai", true)

	tm.AddBytes(1024)
	if tm.BytesTransferred != 1024 {
		t.Errorf("bytes = %d, expected 1024", tm.BytesTransferred)
	}

	tm.AddBytes(512)
	if tm.BytesTransferred != 1536 {
		t.Errorf("bytes = %d, expected 1536", tm.BytesTransferred)
	}
}

func TestTunnelMetricsSetEstimatedCost(t *testing.T) {
	tm := NewTunnelMetrics("openai", true)

	tm.SetEstimatedCost(0.05)
	if tm.EstimatedCost != 0.05 {
		t.Errorf("cost = %f, expected 0.05", tm.EstimatedCost)
	}

	tm.SetEstimatedCost(0.10)
	if tm.EstimatedCost != 0.10 {
		t.Errorf("cost = %f, expected 0.10", tm.EstimatedCost)
	}
}

func TestTunnelMetricsGetDuration(t *testing.T) {
	tm := NewTunnelMetrics("openai", true)

	time.Sleep(100 * time.Millisecond)
	duration := tm.GetDuration()

	if duration < 100*time.Millisecond {
		t.Errorf("duration = %v, expected >= 100ms", duration)
	}
}

func TestTunnelMetricsGetStats(t *testing.T) {
	tm := NewTunnelMetrics("openai", true)

	tm.AddBytes(2048)
	tm.SetEstimatedCost(0.08)

	time.Sleep(50 * time.Millisecond)
	duration, bytes, cost := tm.GetStats()

	if bytes != 2048 {
		t.Errorf("bytes = %d, expected 2048", bytes)
	}
	if cost != 0.08 {
		t.Errorf("cost = %f, expected 0.08", cost)
	}
	if duration < 50*time.Millisecond {
		t.Errorf("duration = %v, expected >= 50ms", duration)
	}
}

func TestTunnelMetricsConcurrency(t *testing.T) {
	tm := NewTunnelMetrics("openai", true)

	// Concurrent writes
	for i := 0; i < 100; i++ {
		go func() {
			tm.AddBytes(10)
		}()
	}

	// Concurrent reads
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			_ = tm.GetDuration()
			_, _, _ = tm.GetStats()
			done <- true
		}()
	}

	// Wait for reads
	for i := 0; i < 10; i++ {
		<-done
	}

	// Final bytes should be correct
	_, bytes, _ := tm.GetStats()
	if bytes == 0 {
		t.Error("bytes should be > 0 after concurrent operations")
	}
}

func TestMetricsCollectorFullWorkflow(t *testing.T) {
	mc := NewMetricsCollector("test")

	// Simulate a tunnel
	mc.RecordTunnelEstablished()
	defer func() {
		mc.RecordTunnelClosed(2*time.Second, 5120)
	}()

	// Detect AI provider
	mc.RecordAIProviderDetected("openai")

	// Record data transfer
	mc.RecordDataTransfer("openai", 1024, 2048)

	// Record latency
	mc.RecordRequestLatency("openai", 150*time.Millisecond)

	// Record cost
	mc.RecordEstimatedCost("openai", 0.05)

	// Verify provider metrics exist
	pm := mc.GetProviderMetrics("openai")
	if pm == nil {
		t.Fatal("provider metrics not created")
	}

	// Verify all metrics callable
	all := mc.GetAllProviderMetrics()
	if len(all) == 0 {
		t.Error("no provider metrics found")
	}
}

func BenchmarkRecordTunnelEstablished(b *testing.B) {
	mc := NewMetricsCollector("bench")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		mc.RecordTunnelEstablished()
	}
}

func BenchmarkRecordAIProviderDetected(b *testing.B) {
	mc := NewMetricsCollector("bench")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		mc.RecordAIProviderDetected("openai")
	}
}

func BenchmarkTunnelMetricsAddBytes(b *testing.B) {
	tm := NewTunnelMetrics("openai", true)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		tm.AddBytes(1024)
	}
}
