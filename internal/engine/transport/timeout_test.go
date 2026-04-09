package transport

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSyntheticDelayExecutes(t *testing.T) {
	called := false
	modifyFn := func(resp *http.Response) error {
		called = true
		return nil
	}

	timeout := 50 * time.Millisecond
	tr := SyntheticDelay(timeout, modifyFn)

	req := httptest.NewRequest("GET", "http://example.com", nil)

	start := time.Now()
	resp, err := tr.RoundTrip(req)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}

	if resp == nil {
		t.Fatal("response is nil")
	}

	if !called {
		t.Error("modify function was not called")
	}

	// Should have waited for the delay duration
	if duration < timeout {
		t.Errorf("delay duration not respected: %v < %v", duration, timeout)
	}

	// But shouldn't be much longer (within 50ms tolerance)
	maxDuration := timeout + 50*time.Millisecond
	if duration > maxDuration {
		t.Errorf("delay took too long: %v > %v", duration, maxDuration)
	}
}

func TestSyntheticDelayModifyFunction(t *testing.T) {
	headerKey := "X-Custom-Header"
	headerValue := "test-value"

	modifyFn := func(resp *http.Response) error {
		resp.Header.Set(headerKey, headerValue)
		return nil
	}

	tr := SyntheticDelay(1*time.Millisecond, modifyFn)

	req := httptest.NewRequest("GET", "http://example.com", nil)
	resp, err := tr.RoundTrip(req)

	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}

	if resp.Header.Get(headerKey) != headerValue {
		t.Errorf("header not set: got %s, want %s", resp.Header.Get(headerKey), headerValue)
	}
}

func TestSyntheticDelayZeroDuration(t *testing.T) {
	called := false
	modifyFn := func(resp *http.Response) error {
		called = true
		return nil
	}

	tr := SyntheticDelay(0, modifyFn)

	req := httptest.NewRequest("GET", "http://example.com", nil)

	start := time.Now()
	_, err := tr.RoundTrip(req)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}

	if !called {
		t.Error("modify function should still be called with zero delay")
	}

	// Should be almost instant
	if duration > 10*time.Millisecond {
		t.Errorf("zero delay took too long: %v", duration)
	}
}

func TestSyntheticDelayLongDuration(t *testing.T) {
	modifyFn := func(resp *http.Response) error {
		return nil
	}

	timeout := 200 * time.Millisecond
	tr := SyntheticDelay(timeout, modifyFn)

	req := httptest.NewRequest("GET", "http://example.com", nil)

	start := time.Now()
	_, err := tr.RoundTrip(req)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}

	if duration < timeout {
		t.Errorf("delay not respected: %v < %v", duration, timeout)
	}
}

func TestSyntheticDelayResponseProperties(t *testing.T) {
	modifyFn := func(resp *http.Response) error {
		return nil
	}

	tr := SyntheticDelay(1*time.Millisecond, modifyFn)

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	resp, err := tr.RoundTrip(req)

	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}

	// Since it wraps Null transport
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, resp.StatusCode)
	}

	if resp.Body != http.NoBody {
		t.Error("expected NoBody for Null transport")
	}

	if resp.Request != req {
		t.Error("response should include original request")
	}
}

// Benchmark tests

func BenchmarkSyntheticDelay(b *testing.B) {
	b.ReportAllocs()
	modifyFn := func(resp *http.Response) error {
		return nil
	}

	tr := SyntheticDelay(1*time.Millisecond, modifyFn)
	req := httptest.NewRequest("GET", "http://example.com", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr.RoundTrip(req)
	}
}

func BenchmarkSyntheticDelayZero(b *testing.B) {
	b.ReportAllocs()
	modifyFn := func(resp *http.Response) error {
		return nil
	}

	tr := SyntheticDelay(0, modifyFn)
	req := httptest.NewRequest("GET", "http://example.com", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr.RoundTrip(req)
	}
}

func BenchmarkSyntheticDelayWithModification(b *testing.B) {
	b.ReportAllocs()
	modifyFn := func(resp *http.Response) error {
		resp.Header.Set("X-Custom", "value")
		resp.Header.Set("X-Timestamp", time.Now().String())
		return nil
	}

	tr := SyntheticDelay(1*time.Millisecond, modifyFn)
	req := httptest.NewRequest("GET", "http://example.com", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr.RoundTrip(req)
	}
}
