package mcp

import (
	"errors"
	"testing"
	"time"
)

func TestNewMetrics(t *testing.T) {
	m := NewMetrics()
	if m == nil {
		t.Fatal("expected non-nil Metrics")
	}
	all := m.GetAllMetrics()
	if len(all) != 0 {
		t.Errorf("expected empty metrics, got %d entries", len(all))
	}
}

func TestMetrics_RecordCall_Success(t *testing.T) {
	m := NewMetrics()
	m.RecordCall("search", 100*time.Millisecond, nil)
	m.RecordCall("search", 200*time.Millisecond, nil)

	tm := m.GetToolMetrics("search")
	if tm == nil {
		t.Fatal("expected non-nil ToolMetrics")
	}
	if tm.TotalCalls != 2 {
		t.Errorf("expected 2 total calls, got %d", tm.TotalCalls)
	}
	if tm.ErrorCalls != 0 {
		t.Errorf("expected 0 error calls, got %d", tm.ErrorCalls)
	}
	if tm.TotalLatency != 300*time.Millisecond {
		t.Errorf("expected 300ms total latency, got %v", tm.TotalLatency)
	}
	if tm.LastCalled.IsZero() {
		t.Error("expected non-zero LastCalled")
	}
}

func TestMetrics_RecordCall_WithErrors(t *testing.T) {
	m := NewMetrics()
	m.RecordCall("deploy", 50*time.Millisecond, nil)
	m.RecordCall("deploy", 75*time.Millisecond, errors.New("timeout"))
	m.RecordCall("deploy", 30*time.Millisecond, errors.New("connection refused"))

	tm := m.GetToolMetrics("deploy")
	if tm == nil {
		t.Fatal("expected non-nil ToolMetrics")
	}
	if tm.TotalCalls != 3 {
		t.Errorf("expected 3 total calls, got %d", tm.TotalCalls)
	}
	if tm.ErrorCalls != 2 {
		t.Errorf("expected 2 error calls, got %d", tm.ErrorCalls)
	}
}

func TestMetrics_GetToolMetrics_NotFound(t *testing.T) {
	m := NewMetrics()
	tm := m.GetToolMetrics("nonexistent")
	if tm != nil {
		t.Error("expected nil for nonexistent tool")
	}
}

func TestMetrics_GetAllMetrics(t *testing.T) {
	m := NewMetrics()
	m.RecordCall("tool_a", 10*time.Millisecond, nil)
	m.RecordCall("tool_b", 20*time.Millisecond, nil)
	m.RecordCall("tool_a", 15*time.Millisecond, nil)

	all := m.GetAllMetrics()
	if len(all) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(all))
	}
	if all["tool_a"].TotalCalls != 2 {
		t.Errorf("expected 2 calls for tool_a, got %d", all["tool_a"].TotalCalls)
	}
	if all["tool_b"].TotalCalls != 1 {
		t.Errorf("expected 1 call for tool_b, got %d", all["tool_b"].TotalCalls)
	}
}

func TestMetrics_GetAllMetrics_ReturnsCopy(t *testing.T) {
	m := NewMetrics()
	m.RecordCall("tool_a", 10*time.Millisecond, nil)

	all := m.GetAllMetrics()
	all["tool_a"].TotalCalls = 999

	// Original should be unchanged
	tm := m.GetToolMetrics("tool_a")
	if tm.TotalCalls != 1 {
		t.Error("GetAllMetrics should return copies, not references")
	}
}

func TestMetrics_Reset(t *testing.T) {
	m := NewMetrics()
	m.RecordCall("search", 50*time.Millisecond, nil)
	m.Reset()

	all := m.GetAllMetrics()
	if len(all) != 0 {
		t.Errorf("expected empty metrics after reset, got %d", len(all))
	}
}

func TestToolMetrics_AverageLatency(t *testing.T) {
	tm := &ToolMetrics{
		TotalCalls:   4,
		TotalLatency: 400 * time.Millisecond,
	}
	avg := tm.AverageLatency()
	if avg != 100*time.Millisecond {
		t.Errorf("expected 100ms average, got %v", avg)
	}
}

func TestToolMetrics_AverageLatency_ZeroCalls(t *testing.T) {
	tm := &ToolMetrics{}
	avg := tm.AverageLatency()
	if avg != 0 {
		t.Errorf("expected 0 average for zero calls, got %v", avg)
	}
}

func TestToolMetrics_ErrorRate(t *testing.T) {
	tests := []struct {
		name       string
		total      int64
		errors     int64
		wantRate   float64
	}{
		{"no calls", 0, 0, 0},
		{"no errors", 10, 0, 0},
		{"all errors", 5, 5, 1.0},
		{"half errors", 10, 5, 0.5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tm := &ToolMetrics{TotalCalls: tt.total, ErrorCalls: tt.errors}
			rate := tm.ErrorRate()
			if rate != tt.wantRate {
				t.Errorf("ErrorRate() = %f, want %f", rate, tt.wantRate)
			}
		})
	}
}
