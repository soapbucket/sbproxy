package routing

import (
	"testing"
)

func TestFillFirstRouter_SelectFirstProvider(t *testing.T) {
	r := NewFillFirstRouter([]string{"a", "b", "c"}, FillFirstConfig{MaxRequestsPerProvider: 2})

	got, ok := r.Select()
	if !ok || got != "a" {
		t.Errorf("expected 'a', got %q (ok=%v)", got, ok)
	}
}

func TestFillFirstRouter_Overflow(t *testing.T) {
	r := NewFillFirstRouter([]string{"a", "b", "c"}, FillFirstConfig{MaxRequestsPerProvider: 2})

	// Exhaust "a"
	r.RecordRequest("a")
	r.RecordRequest("a")

	got, ok := r.Select()
	if !ok || got != "b" {
		t.Errorf("expected 'b' after exhausting 'a', got %q (ok=%v)", got, ok)
	}
}

func TestFillFirstRouter_AllExhausted(t *testing.T) {
	r := NewFillFirstRouter([]string{"a", "b"}, FillFirstConfig{MaxRequestsPerProvider: 1})

	r.RecordRequest("a")
	r.RecordRequest("b")

	_, ok := r.Select()
	if ok {
		t.Error("expected ok=false when all providers are exhausted")
	}
}

func TestFillFirstRouter_Reset(t *testing.T) {
	r := NewFillFirstRouter([]string{"a", "b"}, FillFirstConfig{MaxRequestsPerProvider: 1})

	r.RecordRequest("a")
	r.RecordRequest("b")

	r.Reset()

	got, ok := r.Select()
	if !ok || got != "a" {
		t.Errorf("expected 'a' after reset, got %q (ok=%v)", got, ok)
	}
}

func TestFillFirstRouter_NoLimit(t *testing.T) {
	r := NewFillFirstRouter([]string{"a", "b"}, FillFirstConfig{MaxRequestsPerProvider: 0})

	// Record many requests for "a"; since limit is 0, it should always return "a"
	for i := 0; i < 100; i++ {
		r.RecordRequest("a")
	}

	got, ok := r.Select()
	if !ok || got != "a" {
		t.Errorf("expected 'a' with no limit, got %q (ok=%v)", got, ok)
	}
}

func TestFillFirstRouter_EmptyProviders(t *testing.T) {
	r := NewFillFirstRouter(nil, FillFirstConfig{MaxRequestsPerProvider: 10})

	_, ok := r.Select()
	if ok {
		t.Error("expected ok=false for empty providers")
	}
}

func TestFillFirstRouter_RecordUnknownProvider(t *testing.T) {
	r := NewFillFirstRouter([]string{"a"}, FillFirstConfig{MaxRequestsPerProvider: 10})

	// Should not panic
	r.RecordRequest("unknown")

	got, ok := r.Select()
	if !ok || got != "a" {
		t.Errorf("expected 'a', got %q (ok=%v)", got, ok)
	}
}
