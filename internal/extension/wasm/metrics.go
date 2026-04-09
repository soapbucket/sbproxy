package wasm

import (
	"sync"
	"sync/atomic"
	"time"
)

// PluginMetrics tracks execution metrics for a WASM plugin.
type PluginMetrics struct {
	TotalCalls    atomic.Int64
	TotalErrors   atomic.Int64
	TotalDuration atomic.Int64 // nanoseconds
	LastExecTime  atomic.Int64 // unix nano
}

// RecordExecution records a plugin execution with its duration and optional error.
func (m *PluginMetrics) RecordExecution(duration time.Duration, err error) {
	m.TotalCalls.Add(1)
	m.TotalDuration.Add(int64(duration))
	m.LastExecTime.Store(time.Now().UnixNano())
	if err != nil {
		m.TotalErrors.Add(1)
	}
}

// AverageLatency returns the average execution duration across all calls.
func (m *PluginMetrics) AverageLatency() time.Duration {
	calls := m.TotalCalls.Load()
	if calls == 0 {
		return 0
	}
	return time.Duration(m.TotalDuration.Load() / calls)
}

// ErrorRate returns the ratio of errors to total calls.
func (m *PluginMetrics) ErrorRate() float64 {
	calls := m.TotalCalls.Load()
	if calls == 0 {
		return 0
	}
	return float64(m.TotalErrors.Load()) / float64(calls)
}

// MetricsRegistry tracks metrics for all loaded plugins.
type MetricsRegistry struct {
	metrics map[string]*PluginMetrics
	mu      sync.RWMutex
}

// NewMetricsRegistry creates a new MetricsRegistry.
func NewMetricsRegistry() *MetricsRegistry {
	return &MetricsRegistry{metrics: make(map[string]*PluginMetrics)}
}

// Get returns the metrics for a plugin, creating them if needed.
func (r *MetricsRegistry) Get(pluginName string) *PluginMetrics {
	r.mu.RLock()
	m, ok := r.metrics[pluginName]
	r.mu.RUnlock()
	if ok {
		return m
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok = r.metrics[pluginName]
	if !ok {
		m = &PluginMetrics{}
		r.metrics[pluginName] = m
	}
	return m
}

// All returns a snapshot of all plugin metrics.
func (r *MetricsRegistry) All() map[string]*PluginMetrics {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make(map[string]*PluginMetrics, len(r.metrics))
	for k, v := range r.metrics {
		result[k] = v
	}
	return result
}
