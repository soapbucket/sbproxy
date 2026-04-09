package config

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParsePriorityHeader_Default(t *testing.T) {
	urgency, incremental := parsePriorityHeader("")
	if urgency != 3 {
		t.Errorf("default urgency = %d, want 3", urgency)
	}
	if incremental {
		t.Error("default incremental should be false")
	}
}

func TestParsePriorityHeader_UrgencyOnly(t *testing.T) {
	tests := []struct {
		header      string
		wantUrgency int
		wantIncr    bool
	}{
		{"u=0", 0, false},
		{"u=1", 1, false},
		{"u=3", 3, false},
		{"u=7", 7, false},
	}

	for _, tt := range tests {
		urgency, incr := parsePriorityHeader(tt.header)
		if urgency != tt.wantUrgency {
			t.Errorf("parsePriorityHeader(%q) urgency = %d, want %d", tt.header, urgency, tt.wantUrgency)
		}
		if incr != tt.wantIncr {
			t.Errorf("parsePriorityHeader(%q) incremental = %v, want %v", tt.header, incr, tt.wantIncr)
		}
	}
}

func TestParsePriorityHeader_WithIncremental(t *testing.T) {
	urgency, incremental := parsePriorityHeader("u=2, i")
	if urgency != 2 {
		t.Errorf("urgency = %d, want 2", urgency)
	}
	if !incremental {
		t.Error("incremental should be true")
	}
}

func TestParsePriorityHeader_IncrementalOnly(t *testing.T) {
	urgency, incremental := parsePriorityHeader("i")
	if urgency != 3 {
		t.Errorf("urgency = %d, want 3 (default)", urgency)
	}
	if !incremental {
		t.Error("incremental should be true")
	}
}

func TestParsePriorityHeader_InvalidUrgency(t *testing.T) {
	tests := []struct {
		header      string
		wantUrgency int
	}{
		{"u=8", 3},  // Out of range, use default
		{"u=-1", 3}, // Negative, use default
		{"u=abc", 3}, // Non-numeric, use default
	}

	for _, tt := range tests {
		urgency, _ := parsePriorityHeader(tt.header)
		if urgency != tt.wantUrgency {
			t.Errorf("parsePriorityHeader(%q) urgency = %d, want %d", tt.header, urgency, tt.wantUrgency)
		}
	}
}

func TestPriorityResponseWriter_HighUrgency(t *testing.T) {
	rec := httptest.NewRecorder()
	cfg := &PrioritySchedulerConfig{Enable: true}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Priority", "u=1")

	pw := NewPriorityResponseWriter(rec, req, cfg)

	if pw.Urgency() != 1 {
		t.Errorf("urgency = %d, want 1", pw.Urgency())
	}
	if pw.bufSize != 0 {
		t.Errorf("high urgency bufSize = %d, want 0 (immediate flush)", pw.bufSize)
	}

	data := []byte("high priority response")
	n, err := pw.Write(data)
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != len(data) {
		t.Errorf("wrote %d bytes, want %d", n, len(data))
	}
	if rec.Body.String() != "high priority response" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "high priority response")
	}
}

func TestPriorityResponseWriter_MediumUrgency(t *testing.T) {
	rec := httptest.NewRecorder()
	cfg := &PrioritySchedulerConfig{Enable: true}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Priority", "u=4")

	pw := NewPriorityResponseWriter(rec, req, cfg)

	if pw.Urgency() != 4 {
		t.Errorf("urgency = %d, want 4", pw.Urgency())
	}
	if pw.bufSize != 4096 {
		t.Errorf("medium urgency bufSize = %d, want 4096", pw.bufSize)
	}

	// Write small data - should be buffered
	smallData := []byte("small")
	n, err := pw.Write(smallData)
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != len(smallData) {
		t.Errorf("wrote %d bytes, want %d", n, len(smallData))
	}
	if rec.Body.Len() != 0 {
		t.Error("small data should be buffered, not written yet")
	}

	// Explicit flush should write buffered data
	pw.Flush()
	if rec.Body.String() != "small" {
		t.Errorf("after flush, body = %q, want %q", rec.Body.String(), "small")
	}
}

func TestPriorityResponseWriter_LowUrgency(t *testing.T) {
	rec := httptest.NewRecorder()
	cfg := &PrioritySchedulerConfig{Enable: true}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Priority", "u=7")

	pw := NewPriorityResponseWriter(rec, req, cfg)

	if pw.Urgency() != 7 {
		t.Errorf("urgency = %d, want 7", pw.Urgency())
	}
	if pw.bufSize != 32768 {
		t.Errorf("low urgency bufSize = %d, want 32768", pw.bufSize)
	}
}

func TestPriorityResponseWriter_Incremental(t *testing.T) {
	rec := httptest.NewRecorder()
	cfg := &PrioritySchedulerConfig{Enable: true}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Priority", "u=5, i")

	pw := NewPriorityResponseWriter(rec, req, cfg)

	if !pw.Incremental() {
		t.Error("incremental should be true")
	}
	if pw.bufSize != 0 {
		t.Errorf("incremental bufSize = %d, want 0 (immediate flush)", pw.bufSize)
	}

	data := []byte("streaming data")
	_, err := pw.Write(data)
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if rec.Body.String() != "streaming data" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "streaming data")
	}
}

func TestPriorityResponseWriter_Disabled(t *testing.T) {
	rec := httptest.NewRecorder()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Priority", "u=0")

	// nil config
	pw := NewPriorityResponseWriter(rec, req, nil)
	if pw.urgency != defaultUrgency {
		t.Errorf("disabled urgency = %d, want %d", pw.urgency, defaultUrgency)
	}

	// Disabled config
	pw2 := NewPriorityResponseWriter(rec, req, &PrioritySchedulerConfig{Enable: false})
	if pw2.urgency != defaultUrgency {
		t.Errorf("disabled urgency = %d, want %d", pw2.urgency, defaultUrgency)
	}
}

func TestPriorityResponseWriter_BufferOverflow(t *testing.T) {
	rec := httptest.NewRecorder()
	cfg := &PrioritySchedulerConfig{Enable: true}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Priority", "u=4") // Medium: 4KB buffer

	pw := NewPriorityResponseWriter(rec, req, cfg)

	// Write more than bufSize to trigger flush
	bigData := make([]byte, 5000)
	for i := range bigData {
		bigData[i] = 'x'
	}

	_, err := pw.Write(bigData)
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}

	// Should have flushed because data exceeded buffer size
	if rec.Body.Len() != 5000 {
		t.Errorf("body length = %d, want 5000 (should have flushed)", rec.Body.Len())
	}
}

func TestPriorityResponseWriter_Unwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	pw := &PriorityResponseWriter{
		ResponseWriter: rec,
		urgency:        3,
	}

	unwrapped := pw.Unwrap()
	if unwrapped != rec {
		t.Error("Unwrap should return the underlying ResponseWriter")
	}
}

func TestPriorityResponseWriter_NoPriorityHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	cfg := &PrioritySchedulerConfig{Enable: true}

	req := httptest.NewRequest("GET", "/", nil)
	// No Priority header

	pw := NewPriorityResponseWriter(rec, req, cfg)

	// Should use default urgency (3) which is medium
	if pw.Urgency() != 3 {
		t.Errorf("urgency = %d, want 3 (default)", pw.Urgency())
	}
	if pw.bufSize != 4096 {
		t.Errorf("default bufSize = %d, want 4096", pw.bufSize)
	}
}

func TestPriorityResponseWriter_WriteHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	cfg := &PrioritySchedulerConfig{Enable: true}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Priority", "u=0")

	pw := NewPriorityResponseWriter(rec, req, cfg)
	pw.WriteHeader(http.StatusCreated)

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
}
