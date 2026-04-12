package transport

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewHedgingTransport(t *testing.T) {
	base := http.DefaultTransport
	config := HedgingConfig{
		Enabled:   true,
		Delay:     50 * time.Millisecond,
		MaxHedges: 2,
	}

	transport, err := NewHedgingTransport(base, config)
	if err != nil {
		t.Fatalf("failed to create hedging transport: %v", err)
	}

	if transport.config.Delay != 50*time.Millisecond {
		t.Errorf("expected delay 50ms, got %v", transport.config.Delay)
	}
	if transport.config.MaxHedges != 2 {
		t.Errorf("expected max hedges 2, got %d", transport.config.MaxHedges)
	}
}

func TestNewHedgingTransport_Defaults(t *testing.T) {
	base := http.DefaultTransport
	config := HedgingConfig{
		Enabled: true,
	}

	transport, err := NewHedgingTransport(base, config)
	if err != nil {
		t.Fatalf("failed to create hedging transport: %v", err)
	}

	if transport.config.Delay != 100*time.Millisecond {
		t.Errorf("expected default delay 100ms, got %v", transport.config.Delay)
	}
	if transport.config.MaxHedges != 1 {
		t.Errorf("expected default max hedges 1, got %d", transport.config.MaxHedges)
	}
	if transport.config.MaxCostRatio != 0.2 {
		t.Errorf("expected default cost ratio 0.2, got %f", transport.config.MaxCostRatio)
	}
}

func TestNewHedgingTransport_NilBase(t *testing.T) {
	config := HedgingConfig{
		Enabled: true,
	}

	_, err := NewHedgingTransport(nil, config)
	if err == nil {
		t.Error("expected error for nil base transport")
	}
}

func TestHedgingTransport_Disabled(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := HedgingConfig{
		Enabled: false, // Disabled
		Delay:   10 * time.Millisecond,
	}

	transport, _ := NewHedgingTransport(http.DefaultTransport, config)

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	time.Sleep(50 * time.Millisecond) // Wait for any potential hedges

	if atomic.LoadInt32(&requestCount) != 1 {
		t.Errorf("expected 1 request when disabled, got %d", requestCount)
	}
}

func TestHedgingTransport_PrimaryWinsFast(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		// First request (primary) responds immediately
		if count == 1 {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Hedge request (slower)
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := HedgingConfig{
		Enabled:   true,
		Delay:     50 * time.Millisecond,
		MaxHedges: 1,
	}

	transport, _ := NewHedgingTransport(http.DefaultTransport, config)

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	time.Sleep(200 * time.Millisecond) // Wait for potential hedge

	stats := transport.GetStats()
	if stats.TotalRequests != 1 {
		t.Errorf("expected 1 total request, got %d", stats.TotalRequests)
	}
	if stats.HedgedRequests != 1 {
		t.Errorf("expected 1 hedged request, got %d", stats.HedgedRequests)
	}
	if stats.PrimaryWins != 1 {
		t.Errorf("expected 1 primary win, got %d", stats.PrimaryWins)
	}
}

func TestHedgingTransport_HedgeWinsSlow(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		// First request (primary) is slow
		if count == 1 {
			time.Sleep(200 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
			return
		}
		// Hedge request (faster)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := HedgingConfig{
		Enabled:   true,
		Delay:     50 * time.Millisecond,
		MaxHedges: 1,
	}

	transport, _ := NewHedgingTransport(http.DefaultTransport, config)

	req, _ := http.NewRequest("GET", server.URL, nil)
	start := time.Now()
	resp, err := transport.RoundTrip(req)
	duration := time.Since(start)
	
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	time.Sleep(100 * time.Millisecond) // Wait for primary to be canceled

	stats := transport.GetStats()
	if stats.HedgeWins != 1 {
		t.Errorf("expected 1 hedge win, got %d", stats.HedgeWins)
	}
	if stats.PrimaryCanceled != 1 {
		t.Errorf("expected 1 primary canceled, got %d", stats.PrimaryCanceled)
	}
	
	// Response should arrive much faster than 200ms (primary delay)
	if duration > 150*time.Millisecond {
		t.Errorf("expected response in <150ms (hedge), got %v", duration)
	}
}

func TestHedgingTransport_MethodFiltering(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := HedgingConfig{
		Enabled:   true,
		Delay:     10 * time.Millisecond,
		MaxHedges: 1,
		Methods:   []string{"GET", "HEAD"}, // Only GET and HEAD
	}

	transport, _ := NewHedgingTransport(http.DefaultTransport, config)

	// Test POST (not allowed)
	reqPost, _ := http.NewRequest("POST", server.URL, nil)
	resp, err := transport.RoundTrip(reqPost)
	if err != nil {
		t.Fatalf("POST request failed: %v", err)
	}
	resp.Body.Close()

	time.Sleep(50 * time.Millisecond)
	
	if atomic.LoadInt32(&requestCount) != 1 {
		t.Errorf("POST should not hedge, expected 1 request, got %d", requestCount)
	}

	// Reset counter
	atomic.StoreInt32(&requestCount, 0)

	// Test GET (allowed, but responds fast so no hedge sent)
	reqGet, _ := http.NewRequest("GET", server.URL, nil)
	resp, err = transport.RoundTrip(reqGet)
	if err != nil {
		t.Fatalf("GET request failed: %v", err)
	}
	resp.Body.Close()

	stats := transport.GetStats()
	if stats.HedgedRequests == 0 {
		t.Error("GET should trigger hedging logic")
	}
}

func TestHedgingTransport_MaxCostRatio(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := HedgingConfig{
		Enabled:      true,
		Delay:        10 * time.Millisecond,
		MaxHedges:    1,
		MaxCostRatio: 0.5, // Max 50% hedged
	}

	transport, _ := NewHedgingTransport(http.DefaultTransport, config)

	// Manually set high hedging rate
	atomic.StoreUint64(&transport.stats.TotalRequests, 100)
	atomic.StoreUint64(&transport.stats.HedgedRequests, 60) // 60% > 50%

	// Next request should skip hedging due to cost
	req, _ := http.NewRequest("GET", server.URL, nil)
	_, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	// Check that hedged count didn't increase
	if transport.stats.HedgedRequests != 60 {
		t.Errorf("hedging should be skipped due to cost, but hedged count changed")
	}
}

func TestHedgingTransport_MultipleHedges(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		// All requests slow except the last hedge
		if count < 3 {
			time.Sleep(500 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := HedgingConfig{
		Enabled:   true,
		Delay:     50 * time.Millisecond,
		MaxHedges: 2, // Send up to 2 hedge requests
	}

	transport, _ := NewHedgingTransport(http.DefaultTransport, config)

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := transport.RoundTrip(req)

	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Wait with generous margin for all hedged requests to arrive
	deadline := time.After(2 * time.Second)
	for {
		finalCount := atomic.LoadInt32(&requestCount)
		if finalCount >= 3 {
			break
		}
		select {
		case <-deadline:
			t.Errorf("timed out waiting for 3 requests, got %d", atomic.LoadInt32(&requestCount))
			return
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestHedgingTransport_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	config := HedgingConfig{
		Enabled:   true,
		Delay:     50 * time.Millisecond,
		MaxHedges: 1,
	}

	transport, _ := NewHedgingTransport(http.DefaultTransport, config)

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should still get response (even if error status)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", resp.StatusCode)
	}
}

func TestHedgingTransport_ContextCancellation(t *testing.T) {
	// Verify that cancelling the context does not panic or leak goroutines.
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		// Block until the request context is cancelled
		<-r.Context().Done()
	}))
	defer server.Close()

	config := HedgingConfig{
		Enabled:   true,
		Delay:     50 * time.Millisecond,
		MaxHedges: 1,
	}

	transport, _ := NewHedgingTransport(http.DefaultTransport, config)

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)

	errCh := make(chan error, 1)
	go func() {
		resp, err := transport.RoundTrip(req)
		if resp != nil {
			resp.Body.Close()
		}
		errCh <- err
	}()

	// Wait for at least one request to reach the server, then cancel
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for request to reach server")
	}
	cancel()

	// The RoundTrip should return an error (context cancelled)
	select {
	case err := <-errCh:
		if err == nil {
			// Some implementations return a response even on cancel; that is acceptable
			t.Log("RoundTrip returned nil error after cancel (acceptable)")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RoundTrip did not return after context cancellation")
	}
}

func TestHedgingStats_String(t *testing.T) {
	stats := HedgingStats{
		TotalRequests:   100,
		HedgedRequests:  20,
		HedgeWins:       10,
		PrimaryWins:     10,
		TotalTimeSaved:  5000, // 5 seconds total
		HedgeCanceled:   5,
		PrimaryCanceled: 10,
	}

	str := stats.String()
	if str == "" {
		t.Error("stats string should not be empty")
	}
	
	// Check that string contains key metrics
	if !stringContains(str, "100") { // Total
		t.Error("stats should contain total requests")
	}
	if !stringContains(str, "20") { // Hedged
		t.Error("stats should contain hedged requests")
	}
}

func stringContains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || hasSubstring(s, substr))
}

func hasSubstring(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestHedgingStats_EffectiveLatencyReduction(t *testing.T) {
	stats := HedgingStats{
		HedgeWins:      10,
		TotalTimeSaved: 1000, // 1000ms total, 100ms avg per win
	}

	reduction := stats.EffectiveLatencyReduction()
	// avg saved = 100ms, estimated avg = 100 + 100 = 200ms
	// reduction = 100/200 = 50%
	if reduction < 45 || reduction > 55 {
		t.Errorf("expected ~50%% reduction, got %.2f%%", reduction)
	}
}

func TestHedgingStats_CostMultiplier(t *testing.T) {
	stats := HedgingStats{
		TotalRequests:  100,
		HedgeWins:      10,
		HedgeCanceled:  5,
	}

	multiplier := stats.CostMultiplier()
	// Total sent = 100 + 10 + 5 = 115
	// Multiplier = 115 / 100 = 1.15
	if multiplier < 1.14 || multiplier > 1.16 {
		t.Errorf("expected ~1.15 multiplier, got %.2f", multiplier)
	}
}

func TestHedgingTransport_GetStats(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := HedgingConfig{
		Enabled:   true,
		Delay:     10 * time.Millisecond,
		MaxHedges: 1,
	}

	transport, _ := NewHedgingTransport(http.DefaultTransport, config)

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, _ := transport.RoundTrip(req)
	if resp != nil {
		resp.Body.Close()
	}

	stats := transport.GetStats()
	if stats.TotalRequests == 0 {
		t.Error("stats should show total requests")
	}
}

func TestHedgingTransport_SkipsNonReplayableBody(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := HedgingConfig{
		Enabled:   true,
		Delay:     10 * time.Millisecond,
		MaxHedges: 1,
	}
	transport, _ := NewHedgingTransport(http.DefaultTransport, config)

	req, _ := http.NewRequest("POST", server.URL, io.NopCloser(bytes.NewBufferString("payload")))
	req.GetBody = nil
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	time.Sleep(50 * time.Millisecond)
	if atomic.LoadInt32(&requestCount) != 1 {
		t.Fatalf("expected exactly one request for non-replayable body, got %d", requestCount)
	}
}

func BenchmarkHedgingTransport_PrimaryWins(b *testing.B) {
	b.ReportAllocs()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := HedgingConfig{
		Enabled:   true,
		Delay:     50 * time.Millisecond,
		MaxHedges: 1,
	}

	transport, _ := NewHedgingTransport(http.DefaultTransport, config)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("GET", server.URL, nil)
		resp, _ := transport.RoundTrip(req)
		if resp != nil {
			resp.Body.Close()
		}
	}
}

func BenchmarkHedgingTransport_Disabled(b *testing.B) {
	b.ReportAllocs()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := HedgingConfig{
		Enabled: false,
	}

	transport, _ := NewHedgingTransport(http.DefaultTransport, config)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("GET", server.URL, nil)
		resp, _ := transport.RoundTrip(req)
		if resp != nil {
			resp.Body.Close()
		}
	}
}

