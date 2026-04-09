package config

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestClientConnectionTransportFn_WithRetry(t *testing.T) {
	// Create a test server that fails first 2 requests, then succeeds
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer server.Close()

	// Create transport with retry enabled
	connCfg := &BaseConnection{
		TransportWrappers: &TransportWrapperConfig{
			Retry: &RetryConfig{
				Enabled:      true,
				MaxRetries:   3,
				InitialDelay: reqctx.Duration{Duration: 10 * time.Millisecond},
				MaxDelay:     reqctx.Duration{Duration: 100 * time.Millisecond},
				Multiplier:   2.0,
				Jitter:      0.1,
				RetryableStatus: []int{503},
			},
		},
	}

	tr := ClientConnectionTransportFn(connCfg, server.URL)
	client := &http.Client{Transport: tr}

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	if attempts < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts)
	}
}

func TestClientConnectionTransportFn_WithHedging(t *testing.T) {
	// Create a test server with variable latency
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond) // Simulate slow response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer server.Close()

	connCfg := &BaseConnection{
		TransportWrappers: &TransportWrapperConfig{
			Hedging: &HedgingConfig{
				Enabled:   true,
				Delay:     reqctx.Duration{Duration: 10 * time.Millisecond},
				MaxHedges: 1,
				MaxCostRatio: 0.5,
			},
		},
	}

	tr := ClientConnectionTransportFn(connCfg, server.URL)
	client := &http.Client{Transport: tr}

	req, _ := http.NewRequest("GET", server.URL, nil)
	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Hedging should reduce latency (should complete faster than 50ms due to hedge)
	if duration > 30*time.Millisecond {
		t.Logf("hedging may not have worked as expected, duration: %v", duration)
	}
}

func TestClientConnectionTransportFn_WithHealthCheck(t *testing.T) {
	// Create a test server that starts unhealthy, then becomes healthy
	var healthy atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			if healthy.Load() {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("ok"))
			} else {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer server.Close()

	// Create health check manager
	manager := NewHealthCheckManager()
	SetHealthCheckManager(manager)
	defer manager.StopAll()

	connCfg := &BaseConnection{
		TransportWrappers: &TransportWrapperConfig{
			HealthCheck: &TransportHealthCheckConfig{
				Enabled:          true,
				Type:             "http",
				Endpoint:         "/health",
				Interval:         reqctx.Duration{Duration: 100 * time.Millisecond},
				Timeout:          reqctx.Duration{Duration: 5 * time.Second},
				HealthyThreshold:   1,
				UnhealthyThreshold: 1,
				ExpectedStatus:     200,
			},
		},
	}

	tr := ClientConnectionTransportFn(connCfg, server.URL)
	client := &http.Client{Transport: tr}

	// First request should fail (backend unhealthy)
	req, _ := http.NewRequest("GET", server.URL+"/api", nil)
	_, err := client.Do(req)
	if err == nil {
		t.Error("expected error when backend is unhealthy")
	}

	// Mark backend as healthy
	healthy.Store(true)

	// Wait for health check to update
	time.Sleep(150 * time.Millisecond)

	// Now request should succeed
	req, _ = http.NewRequest("GET", server.URL+"/api", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestClientConnectionTransportFn_WithAllWrappers(t *testing.T) {
	// Create a test server
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
			return
		}
		attempts++
		if attempts <= 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer server.Close()

	// Create health check manager
	manager := NewHealthCheckManager()
	SetHealthCheckManager(manager)
	defer manager.StopAll()

	connCfg := &BaseConnection{
		TransportWrappers: &TransportWrapperConfig{
			HealthCheck: &TransportHealthCheckConfig{
				Enabled:          true,
				Type:             "http",
				Endpoint:         "/health",
				Interval:         reqctx.Duration{Duration: 100 * time.Millisecond},
				Timeout:          reqctx.Duration{Duration: 5 * time.Second},
				HealthyThreshold:   1,
				UnhealthyThreshold: 1,
				ExpectedStatus:     200,
			},
			Hedging: &HedgingConfig{
				Enabled:   true,
				Delay:     reqctx.Duration{Duration: 10 * time.Millisecond},
				MaxHedges: 1,
				MaxCostRatio: 0.5,
			},
			Retry: &RetryConfig{
				Enabled:      true,
				MaxRetries:   2,
				InitialDelay: reqctx.Duration{Duration: 10 * time.Millisecond},
				MaxDelay:     reqctx.Duration{Duration: 100 * time.Millisecond},
				Multiplier:   2.0,
				Jitter:       0.1,
				RetryableStatus: []int{503},
			},
		},
	}

	tr := ClientConnectionTransportFn(connCfg, server.URL)
	client := &http.Client{Transport: tr}

	// Wait for health check to mark backend as healthy
	time.Sleep(150 * time.Millisecond)

	req, _ := http.NewRequest("GET", server.URL+"/api", nil)
	resp, err := client.Do(req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestHealthCheckManager_GetOrCreateHealthChecker(t *testing.T) {
	manager := NewHealthCheckManager()
	defer manager.StopAll()

	cfg := &TransportHealthCheckConfig{
		Enabled:          true,
		Type:             "http",
		Endpoint:         "/health",
		Interval:         reqctx.Duration{Duration: 100 * time.Millisecond},
		Timeout:          reqctx.Duration{Duration: 5 * time.Second},
		HealthyThreshold:   1,
		UnhealthyThreshold: 1,
		ExpectedStatus:     200,
	}

	// Create first checker
	checker1, err := manager.GetOrCreateHealthChecker("origin1", "https://api.example.com", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if checker1 == nil {
		t.Fatal("expected health checker to be created")
	}

	// Get same checker (should return existing)
	checker2, err := manager.GetOrCreateHealthChecker("origin1", "https://api.example.com", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if checker1 != checker2 {
		t.Error("expected same health checker instance")
	}

	// Create different checker for different origin
	checker3, err := manager.GetOrCreateHealthChecker("origin2", "https://api2.example.com", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if checker3 == nil {
		t.Fatal("expected health checker to be created")
	}
	if checker1 == checker3 {
		t.Error("expected different health checker instance for different origin")
	}
}

func TestHealthCheckManager_RemoveHealthChecker(t *testing.T) {
	manager := NewHealthCheckManager()
	defer manager.StopAll()

	cfg := &TransportHealthCheckConfig{
		Enabled:          true,
		Type:             "http",
		Endpoint:         "/health",
		Interval:         reqctx.Duration{Duration: 100 * time.Millisecond},
		Timeout:          reqctx.Duration{Duration: 5 * time.Second},
		HealthyThreshold:   1,
		UnhealthyThreshold: 1,
		ExpectedStatus:     200,
	}

	checker, err := manager.GetOrCreateHealthChecker("origin1", "https://api.example.com", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if checker == nil {
		t.Fatal("expected health checker to be created")
	}

	// Remove checker
	manager.RemoveHealthChecker("origin1")

	// Should not exist anymore
	retrieved := manager.GetHealthChecker("origin1")
	if retrieved != nil {
		t.Error("expected health checker to be removed")
	}
}

