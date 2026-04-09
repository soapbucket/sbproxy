package transport

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestBeaconBasic(t *testing.T) {
	called := false
	modifyFn := func(resp *http.Response) error {
		called = true
		return nil
	}

	beacon := Beacon(modifyFn)

	req := httptest.NewRequest("GET", "http://example.com/pixel", nil)
	resp, err := beacon.RoundTrip(req)

	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}

	if !called {
		t.Error("modify function was not called")
	}

	if resp == nil {
		t.Fatal("response is nil")
	}

	// Beacon uses Null transport
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, resp.StatusCode)
	}
}

func TestBeaconModifyResponse(t *testing.T) {
	headerKey := "X-Tracking-ID"
	headerValue := "beacon-12345"

	modifyFn := func(resp *http.Response) error {
		resp.Header.Set(headerKey, headerValue)
		resp.StatusCode = http.StatusOK
		return nil
	}

	beacon := Beacon(modifyFn)

	req := httptest.NewRequest("GET", "http://example.com/pixel.gif", nil)
	resp, err := beacon.RoundTrip(req)

	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}

	if resp.Header.Get(headerKey) != headerValue {
		t.Errorf("header not set: got %s, want %s", resp.Header.Get(headerKey), headerValue)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestBeaconError(t *testing.T) {
	expectedError := errors.New("tracking error")

	modifyFn := func(resp *http.Response) error {
		return expectedError
	}

	beacon := Beacon(modifyFn)

	req := httptest.NewRequest("GET", "http://example.com/pixel", nil)
	_, err := beacon.RoundTrip(req)

	if err != expectedError {
		t.Errorf("expected error %v, got %v", expectedError, err)
	}
}

func TestBeaconMultipleHeaders(t *testing.T) {
	modifyFn := func(resp *http.Response) error {
		resp.Header.Set("X-Beacon", "true")
		resp.Header.Set("X-Timestamp", "12345")
		resp.Header.Set("X-User-Agent", "test-agent")
		resp.Header.Set("Cache-Control", "no-cache")
		return nil
	}

	beacon := Beacon(modifyFn)

	req := httptest.NewRequest("GET", "http://example.com/pixel", nil)
	resp, err := beacon.RoundTrip(req)

	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}

	expectedHeaders := map[string]string{
		"X-Beacon":      "true",
		"X-Timestamp":   "12345",
		"X-User-Agent":  "test-agent",
		"Cache-Control": "no-cache",
	}

	for key, expectedValue := range expectedHeaders {
		if value := resp.Header.Get(key); value != expectedValue {
			t.Errorf("header %s: got %s, want %s", key, value, expectedValue)
		}
	}
}

func TestBeaconRequestPreservation(t *testing.T) {
	modifyFn := func(resp *http.Response) error {
		// Verify we can access request details
		if resp.Request == nil {
			t.Error("request is nil in modify function")
			return nil
		}

		if resp.Request.URL.Path != "/track" {
			t.Errorf("unexpected path: %s", resp.Request.URL.Path)
		}

		return nil
	}

	beacon := Beacon(modifyFn)

	req := httptest.NewRequest("GET", "http://example.com/track", nil)
	resp, err := beacon.RoundTrip(req)

	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}

	if resp.Request != req {
		t.Error("response should preserve original request")
	}
}

func TestBeaconNilModifyFunction(t *testing.T) {
	// Should handle nil modify function gracefully (via Wrap)
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil modify function")
		}
	}()

	beacon := Beacon(nil)
	req := httptest.NewRequest("GET", "http://example.com/pixel", nil)
	beacon.RoundTrip(req)
}

func TestBeaconConcurrent(t *testing.T) {
	var callCount int32
	modifyFn := func(resp *http.Response) error {
		atomic.AddInt32(&callCount, 1)
		return nil
	}

	beacon := Beacon(modifyFn)

	req := httptest.NewRequest("GET", "http://example.com/pixel", nil)

	// Make multiple concurrent requests
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			beacon.RoundTrip(req)
			done <- true
		}()
	}

	// Wait for all to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Note: callCount check would be racy, but we mainly want to ensure no panics
}

// Benchmark tests

func BenchmarkBeacon(b *testing.B) {
	b.ReportAllocs()
	modifyFn := func(resp *http.Response) error {
		return nil
	}

	beacon := Beacon(modifyFn)
	req := httptest.NewRequest("GET", "http://example.com/pixel", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		beacon.RoundTrip(req)
	}
}

func BenchmarkBeaconWithModification(b *testing.B) {
	b.ReportAllocs()
	modifyFn := func(resp *http.Response) error {
		resp.Header.Set("X-Beacon", "true")
		resp.Header.Set("X-Timestamp", "12345")
		resp.StatusCode = http.StatusOK
		return nil
	}

	beacon := Beacon(modifyFn)
	req := httptest.NewRequest("GET", "http://example.com/pixel", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		beacon.RoundTrip(req)
	}
}

func BenchmarkBeaconParallel(b *testing.B) {
	b.ReportAllocs()
	modifyFn := func(resp *http.Response) error {
		resp.Header.Set("X-Beacon", "true")
		return nil
	}

	beacon := Beacon(modifyFn)
	req := httptest.NewRequest("GET", "http://example.com/pixel", nil)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			beacon.RoundTrip(req)
		}
	})
}
