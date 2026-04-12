// Package mcp implements the Model Context Protocol (MCP) for AI tool and resource integration.
package mcp

import (
	"sync"
	"time"
)

// Metrics tracks MCP tool call metrics.
type Metrics struct {
	toolCalls map[string]*ToolMetrics
	mu        sync.RWMutex
}

// ToolMetrics holds per-tool call statistics.
type ToolMetrics struct {
	TotalCalls   int64         `json:"total_calls"`
	ErrorCalls   int64         `json:"error_calls"`
	TotalLatency time.Duration `json:"total_latency"`
	LastCalled   time.Time     `json:"last_called"`
}

// AverageLatency returns the average latency per call, or zero if no calls recorded.
func (tm *ToolMetrics) AverageLatency() time.Duration {
	if tm.TotalCalls == 0 {
		return 0
	}
	return time.Duration(int64(tm.TotalLatency) / tm.TotalCalls)
}

// ErrorRate returns the fraction of calls that were errors (0.0 to 1.0).
func (tm *ToolMetrics) ErrorRate() float64 {
	if tm.TotalCalls == 0 {
		return 0
	}
	return float64(tm.ErrorCalls) / float64(tm.TotalCalls)
}

// NewMetrics creates a new Metrics tracker.
func NewMetrics() *Metrics {
	return &Metrics{
		toolCalls: make(map[string]*ToolMetrics),
	}
}

// RecordCall records a tool call with its duration and optional error.
func (m *Metrics) RecordCall(toolName string, duration time.Duration, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	tm, ok := m.toolCalls[toolName]
	if !ok {
		tm = &ToolMetrics{}
		m.toolCalls[toolName] = tm
	}

	tm.TotalCalls++
	tm.TotalLatency += duration
	tm.LastCalled = time.Now()

	if err != nil {
		tm.ErrorCalls++
	}
}

// GetToolMetrics returns metrics for a specific tool, or nil if none recorded.
func (m *Metrics) GetToolMetrics(toolName string) *ToolMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tm, ok := m.toolCalls[toolName]
	if !ok {
		return nil
	}

	// Return a copy to avoid data races
	copy := *tm
	return &copy
}

// GetAllMetrics returns a copy of all tool metrics.
func (m *Metrics) GetAllMetrics() map[string]*ToolMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*ToolMetrics, len(m.toolCalls))
	for name, tm := range m.toolCalls {
		copy := *tm
		result[name] = &copy
	}
	return result
}

// Reset clears all recorded metrics.
func (m *Metrics) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.toolCalls = make(map[string]*ToolMetrics)
}
