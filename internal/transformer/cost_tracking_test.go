package transformer

import (
	"errors"
	"testing"
	"time"
)

func TestCostTracker_Record(t *testing.T) {
	ct := NewCostTracker()

	ct.Record("html", "origin1", 5*time.Millisecond, 100, 120, nil)
	ct.Record("html", "origin1", 3*time.Millisecond, 200, 210, nil)

	snapshots := ct.Snapshot()
	if len(snapshots) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(snapshots))
	}

	s := snapshots[0]
	if s.Name != "html" {
		t.Errorf("expected name 'html', got %q", s.Name)
	}
	if s.Executions != 2 {
		t.Errorf("expected 2 executions, got %d", s.Executions)
	}
	if s.TotalDuration != 8*time.Millisecond {
		t.Errorf("expected total duration 8ms, got %v", s.TotalDuration)
	}
	if s.AvgDuration != 4*time.Millisecond {
		t.Errorf("expected avg duration 4ms, got %v", s.AvgDuration)
	}
	if s.BytesIn != 300 {
		t.Errorf("expected bytes in 300, got %d", s.BytesIn)
	}
	if s.BytesOut != 330 {
		t.Errorf("expected bytes out 330, got %d", s.BytesOut)
	}
	if s.Errors != 0 {
		t.Errorf("expected 0 errors, got %d", s.Errors)
	}

	// Record an error.
	ct.Record("html", "origin1", 1*time.Millisecond, 50, 0, errors.New("fail"))

	snapshots = ct.Snapshot()
	if snapshots[0].Errors != 1 {
		t.Errorf("expected 1 error, got %d", snapshots[0].Errors)
	}
	if snapshots[0].Executions != 3 {
		t.Errorf("expected 3 executions, got %d", snapshots[0].Executions)
	}
}

func TestCostTracker_Snapshot(t *testing.T) {
	ct := NewCostTracker()

	ct.Record("slow", "origin1", 10*time.Millisecond, 100, 100, nil)
	ct.Record("fast", "origin1", 1*time.Millisecond, 50, 50, nil)
	ct.Record("medium", "origin1", 5*time.Millisecond, 75, 75, nil)

	snapshots := ct.Snapshot()
	if len(snapshots) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(snapshots))
	}

	// Verify sorted by total duration descending.
	if snapshots[0].Name != "slow" {
		t.Errorf("expected first entry 'slow', got %q", snapshots[0].Name)
	}
	if snapshots[1].Name != "medium" {
		t.Errorf("expected second entry 'medium', got %q", snapshots[1].Name)
	}
	if snapshots[2].Name != "fast" {
		t.Errorf("expected third entry 'fast', got %q", snapshots[2].Name)
	}
}

func TestCostTracker_Reset(t *testing.T) {
	ct := NewCostTracker()

	ct.Record("html", "origin1", 5*time.Millisecond, 100, 120, nil)
	ct.Record("json", "origin1", 3*time.Millisecond, 200, 210, nil)

	if len(ct.Snapshot()) != 2 {
		t.Fatal("expected 2 entries before reset")
	}

	ct.Reset()

	snapshots := ct.Snapshot()
	if len(snapshots) != 0 {
		t.Errorf("expected 0 entries after reset, got %d", len(snapshots))
	}

	// Verify we can record again after reset.
	ct.Record("css", "origin1", 2*time.Millisecond, 50, 55, nil)
	if len(ct.Snapshot()) != 1 {
		t.Error("expected 1 entry after recording post-reset")
	}
}
