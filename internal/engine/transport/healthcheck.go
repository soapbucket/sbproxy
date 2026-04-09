// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HealthCheckType defines the type of health check
type HealthCheckType string

const (
	// HealthCheckHTTP is a constant for health check http.
	HealthCheckHTTP HealthCheckType = "http"
	// HealthCheckHTTPS is a constant for health check https.
	HealthCheckHTTPS HealthCheckType = "https"
	// HealthCheckTCP is a constant for health check tcp.
	HealthCheckTCP  HealthCheckType = "tcp"
)

// HealthStatus represents the health status of a backend
type HealthStatus string

const (
	// HealthStatusHealthy is a constant for health status healthy.
	HealthStatusHealthy   HealthStatus = "healthy"
	// HealthStatusUnhealthy is a constant for health status unhealthy.
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	// HealthStatusUnknown is a constant for health status unknown.
	HealthStatusUnknown   HealthStatus = "unknown"
)

// HealthCheckConfig configures health checking for a backend
type HealthCheckConfig struct {
	// Type of health check (http, https, tcp)
	Type HealthCheckType

	// Endpoint to check (for HTTP/HTTPS)
	Endpoint string

	// Host header to send (optional, for HTTP/HTTPS)
	Host string

	// Interval between health checks
	Interval time.Duration

	// Timeout for each health check
	Timeout time.Duration

	// Number of consecutive successes needed to mark healthy
	HealthyThreshold int

	// Number of consecutive failures needed to mark unhealthy
	UnhealthyThreshold int

	// Expected status code (for HTTP/HTTPS, default: 200)
	ExpectedStatus int

	// Expected response body substring (optional)
	ExpectedBody string
}

// DefaultHealthCheckConfig returns a config with sensible defaults
func DefaultHealthCheckConfig() *HealthCheckConfig {
	return &HealthCheckConfig{
		Type:               HealthCheckHTTP,
		Endpoint:           "/health",
		Interval:           30 * time.Second,
		Timeout:            5 * time.Second,
		HealthyThreshold:   2,
		UnhealthyThreshold: 3,
		ExpectedStatus:     200,
	}
}

// HealthChecker performs health checks on a backend
type HealthChecker struct {
	config *HealthCheckConfig
	target string // Backend URL or address

	mu               sync.RWMutex
	status           HealthStatus
	consecutiveSuccess int
	consecutiveFailures int
	lastCheck        time.Time
	lastError        error

	stopCh chan struct{}
	doneCh chan struct{}
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(target string, config *HealthCheckConfig) *HealthChecker {
	if config == nil {
		config = DefaultHealthCheckConfig()
	}

	// Set defaults if not provided
	if config.Interval == 0 {
		config.Interval = 30 * time.Second
	}
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}
	if config.HealthyThreshold == 0 {
		config.HealthyThreshold = 2
	}
	if config.UnhealthyThreshold == 0 {
		config.UnhealthyThreshold = 3
	}
	if config.ExpectedStatus == 0 {
		config.ExpectedStatus = 200
	}

	return &HealthChecker{
		config: config,
		target: target,
		status: HealthStatusUnknown,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
}

// Start begins periodic health checking.
// It runs an immediate synchronous check so the status is known (healthy or
// unhealthy) before the background loop takes over, avoiding a cold-start
// window where status is "unknown".
func (hc *HealthChecker) Start() {
	hc.performCheck()
	go hc.run()
}

// Stop stops the health checker
func (hc *HealthChecker) Stop() {
	close(hc.stopCh)
	<-hc.doneCh
}

// IsHealthy returns true if the backend is healthy
func (hc *HealthChecker) IsHealthy() bool {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	return hc.status == HealthStatusHealthy
}

// GetStatus returns the current health status
func (hc *HealthChecker) GetStatus() HealthStatus {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	return hc.status
}

// GetLastError returns the last health check error
func (hc *HealthChecker) GetLastError() error {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	return hc.lastError
}

// GetLastCheck returns the time of the last health check
func (hc *HealthChecker) GetLastCheck() time.Time {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	return hc.lastCheck
}

// run is the main health check loop
func (hc *HealthChecker) run() {
	defer close(hc.doneCh)

	// Perform initial check immediately
	hc.performCheck()

	ticker := time.NewTicker(hc.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			hc.performCheck()
		case <-hc.stopCh:
			return
		}
	}
}

// performCheck executes a single health check
func (hc *HealthChecker) performCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), hc.config.Timeout)
	defer cancel()

	var err error
	switch hc.config.Type {
	case HealthCheckHTTP, HealthCheckHTTPS:
		err = hc.checkHTTP(ctx)
	case HealthCheckTCP:
		err = hc.checkTCP(ctx)
	default:
		err = fmt.Errorf("unknown health check type: %s", hc.config.Type)
	}

	hc.updateStatus(err)
}

// checkHTTP performs an HTTP/HTTPS health check
func (hc *HealthChecker) checkHTTP(ctx context.Context) error {
	// Build URL
	scheme := "http"
	if hc.config.Type == HealthCheckHTTPS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s%s", scheme, hc.target, hc.config.Endpoint)

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set Host header if configured
	if hc.config.Host != "" {
		req.Host = hc.config.Host
	}

	// Execute request
	client := &http.Client{
		Timeout: hc.config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("health check request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != hc.config.ExpectedStatus {
		return fmt.Errorf("unexpected status code: got %d, expected %d", resp.StatusCode, hc.config.ExpectedStatus)
	}

	// Check response body if configured
	if hc.config.ExpectedBody != "" {
		body := make([]byte, 1024)
		n, _ := resp.Body.Read(body)
		bodyStr := string(body[:n])
		
		if !strings.Contains(bodyStr, hc.config.ExpectedBody) {
			return fmt.Errorf("expected body substring not found: %q", hc.config.ExpectedBody)
		}
	}

	return nil
}

// checkTCP performs a TCP health check
func (hc *HealthChecker) checkTCP(ctx context.Context) error {
	dialer := &net.Dialer{
		Timeout: hc.config.Timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", hc.target)
	if err != nil {
		return fmt.Errorf("TCP connection failed: %w", err)
	}
	defer conn.Close()

	return nil
}

// updateStatus updates the health status based on check result
func (hc *HealthChecker) updateStatus(err error) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	hc.lastCheck = time.Now()
	hc.lastError = err

	if err != nil {
		// Check failed
		hc.consecutiveSuccess = 0
		hc.consecutiveFailures++

		slog.Debug("health check failed",
			"target", hc.target,
			"consecutive_failures", hc.consecutiveFailures,
			"error", err)

		// Mark unhealthy if threshold reached
		if hc.consecutiveFailures >= hc.config.UnhealthyThreshold {
			if hc.status != HealthStatusUnhealthy {
				slog.Warn("backend marked unhealthy",
					"target", hc.target,
					"consecutive_failures", hc.consecutiveFailures)
				hc.status = HealthStatusUnhealthy
			}
		}
	} else {
		// Check succeeded
		hc.consecutiveFailures = 0
		hc.consecutiveSuccess++

		slog.Debug("health check succeeded",
			"target", hc.target,
			"consecutive_successes", hc.consecutiveSuccess)

		// Mark healthy if threshold reached
		if hc.consecutiveSuccess >= hc.config.HealthyThreshold {
			if hc.status != HealthStatusHealthy {
				slog.Info("backend marked healthy",
					"target", hc.target,
					"consecutive_successes", hc.consecutiveSuccess)
				hc.status = HealthStatusHealthy
			}
		}
	}
}


// HealthCheckTransport wraps a transport with health checking
type HealthCheckTransport struct {
	Base          http.RoundTripper
	HealthChecker *HealthChecker
}

// RoundTrip implements http.RoundTripper
func (t *HealthCheckTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Check if backend is healthy
	if !t.HealthChecker.IsHealthy() {
		return nil, errors.New("backend is unhealthy")
	}

	return t.Base.RoundTrip(req)
}

