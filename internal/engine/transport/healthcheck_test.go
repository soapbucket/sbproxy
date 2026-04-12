package transport

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestHealthChecker_HTTP_Success(t *testing.T) {
	// Create test server that always returns 200
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	// Create health checker
	config := &HealthCheckConfig{
		Type:               HealthCheckHTTP,
		Endpoint:           "/health",
		Interval:           100 * time.Millisecond,
		Timeout:            1 * time.Second,
		HealthyThreshold:   2,
		UnhealthyThreshold: 2,
		ExpectedStatus:     200,
	}

	// Extract host from server URL (remove http://)
	target := server.URL[7:] // Remove "http://"

	hc := NewHealthChecker(target, config)
	hc.Start()
	defer hc.Stop()

	// Wait for health checks to mark as healthy (need 2 successes)
	time.Sleep(300 * time.Millisecond)

	if !hc.IsHealthy() {
		t.Errorf("expected healthy status, got: %v (error: %v)", hc.GetStatus(), hc.GetLastError())
	}
}

func TestHealthChecker_HTTP_Failure(t *testing.T) {
	// Create test server that returns 503
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	config := &HealthCheckConfig{
		Type:               HealthCheckHTTP,
		Endpoint:           "/health",
		Interval:           100 * time.Millisecond,
		Timeout:            1 * time.Second,
		HealthyThreshold:   2,
		UnhealthyThreshold: 2,
		ExpectedStatus:     200,
	}

	target := server.URL[7:]
	hc := NewHealthChecker(target, config)
	hc.Start()
	defer hc.Stop()

	// Wait for health checks to mark as unhealthy (need 2 failures)
	time.Sleep(300 * time.Millisecond)

	if hc.IsHealthy() {
		t.Error("expected unhealthy status, got healthy")
	}

	if hc.GetStatus() != HealthStatusUnhealthy {
		t.Errorf("expected unhealthy status, got: %v", hc.GetStatus())
	}
}

func TestHealthChecker_TCP_Success(t *testing.T) {
	// Create TCP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &HealthCheckConfig{
		Type:               HealthCheckTCP,
		Interval:           100 * time.Millisecond,
		Timeout:            1 * time.Second,
		HealthyThreshold:   2,
		UnhealthyThreshold: 2,
	}

	target := server.URL[7:] // Remove "http://"
	hc := NewHealthChecker(target, config)
	hc.Start()
	defer hc.Stop()

	// Wait for health checks
	time.Sleep(300 * time.Millisecond)

	if !hc.IsHealthy() {
		t.Errorf("expected healthy status for TCP check, got: %v", hc.GetStatus())
	}
}

func TestHealthChecker_TCP_Failure(t *testing.T) {
	config := &HealthCheckConfig{
		Type:               HealthCheckTCP,
		Interval:           100 * time.Millisecond,
		Timeout:            1 * time.Second,
		HealthyThreshold:   2,
		UnhealthyThreshold: 2,
	}

	// Use invalid address
	hc := NewHealthChecker("localhost:99999", config)
	hc.Start()
	defer hc.Stop()

	// Wait for health checks
	time.Sleep(300 * time.Millisecond)

	if hc.IsHealthy() {
		t.Error("expected unhealthy status for invalid TCP address, got healthy")
	}
}

func TestHealthChecker_Thresholds(t *testing.T) {
	var failCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := failCount.Add(1)
		if n <= 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	config := &HealthCheckConfig{
		Type:               HealthCheckHTTP,
		Endpoint:           "/health",
		Interval:           50 * time.Millisecond,
		Timeout:            1 * time.Second,
		HealthyThreshold:   2,
		UnhealthyThreshold: 2,
		ExpectedStatus:     200,
	}

	target := server.URL[7:]
	hc := NewHealthChecker(target, config)
	hc.Start()
	defer hc.Stop()

	// Poll until unhealthy (should happen after 2 failures)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !hc.IsHealthy() {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if hc.IsHealthy() {
		t.Error("should be unhealthy after 2 failures")
	}

	// Poll until healthy (should happen after server starts returning 200)
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hc.IsHealthy() {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !hc.IsHealthy() {
		t.Error("should be healthy after 2 successes")
	}
}

func TestHealthChecker_ExpectedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("healthy: true"))
	}))
	defer server.Close()

	config := &HealthCheckConfig{
		Type:               HealthCheckHTTP,
		Endpoint:           "/health",
		Interval:           100 * time.Millisecond,
		Timeout:            1 * time.Second,
		HealthyThreshold:   2,
		UnhealthyThreshold: 2,
		ExpectedStatus:     200,
		ExpectedBody:       "healthy: true",
	}

	target := server.URL[7:]
	hc := NewHealthChecker(target, config)
	hc.Start()
	defer hc.Stop()

	time.Sleep(300 * time.Millisecond)

	if !hc.IsHealthy() {
		t.Errorf("expected healthy status with matching body, got: %v (error: %v)",
			hc.GetStatus(), hc.GetLastError())
	}
}

func TestHealthChecker_WrongBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("status: degraded"))
	}))
	defer server.Close()

	config := &HealthCheckConfig{
		Type:               HealthCheckHTTP,
		Endpoint:           "/health",
		Interval:           50 * time.Millisecond,
		Timeout:            1 * time.Second,
		HealthyThreshold:   1,
		UnhealthyThreshold: 1,
		ExpectedStatus:     200,
		ExpectedBody:       "status: ok",
	}

	target := server.URL[7:]
	hc := NewHealthChecker(target, config)
	hc.Start()
	defer hc.Stop()

	// Poll until the checker transitions to unhealthy
	deadline := time.After(5 * time.Second)
	for {
		if !hc.IsHealthy() {
			// Verify it is specifically HealthStatusUnhealthy (not just Unknown)
			if status := hc.GetStatus(); status == HealthStatusUnhealthy {
				return // success
			}
		}
		select {
		case <-deadline:
			t.Errorf("expected unhealthy status with non-matching body, got status %v (error: %v)",
				hc.GetStatus(), hc.GetLastError())
			return
		default:
			time.Sleep(25 * time.Millisecond)
		}
	}
}

func TestHealthCheckTransport(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create health checker that starts unhealthy
	config := &HealthCheckConfig{
		Type:               HealthCheckHTTP,
		Endpoint:           "/health",
		Interval:           1 * time.Second, // Long interval
		Timeout:            1 * time.Second,
		HealthyThreshold:   2,
		UnhealthyThreshold: 2,
		ExpectedStatus:     200,
	}

	target := server.URL[7:]
	hc := NewHealthChecker(target, config)

	// Don't start the health checker - status will be unknown/unhealthy

	transport := &HealthCheckTransport{
		Base:          http.DefaultTransport,
		HealthChecker: hc,
	}

	client := &http.Client{Transport: transport}
	req, _ := http.NewRequest("GET", server.URL, nil)

	// Should fail because backend is not marked healthy
	_, err := client.Do(req)
	if err == nil {
		t.Error("expected error for unhealthy backend")
	}

	// Now mark as healthy and try again
	hc.Start()
	defer hc.Stop()

	// Wait for health checks to mark backend as healthy (need 2 successful checks)
	// With 1s interval and 2 healthy threshold, this needs at least 2s + some buffer
	time.Sleep(2500 * time.Millisecond)

	// Retry a few times in case health check is still in progress
	var resp *http.Response
	for i := 0; i < 3; i++ {
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if err != nil {
		t.Errorf("request should succeed with healthy backend: %v", err)
	}
	if resp != nil {
		resp.Body.Close()
	}
}

func TestDefaultHealthCheckConfig(t *testing.T) {
	config := DefaultHealthCheckConfig()

	if config.Type != HealthCheckHTTP {
		t.Errorf("expected HTTP type, got %v", config.Type)
	}
	if config.Endpoint != "/health" {
		t.Errorf("expected /health endpoint, got %v", config.Endpoint)
	}
	if config.Interval != 30*time.Second {
		t.Errorf("expected 30s interval, got %v", config.Interval)
	}
	if config.ExpectedStatus != 200 {
		t.Errorf("expected status 200, got %d", config.ExpectedStatus)
	}
}
