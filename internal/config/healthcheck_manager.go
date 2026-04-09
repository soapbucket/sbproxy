// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"fmt"
	"log/slog"
	"net/url"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/engine/transport"
)

// HealthCheckManager manages health checkers per origin
type HealthCheckManager struct {
	mu       sync.RWMutex
	checkers map[string]*transport.HealthChecker // key: origin URL or origin ID
	configs  map[string]*TransportHealthCheckConfig        // key: origin URL or origin ID
}

// NewHealthCheckManager creates a new health check manager
func NewHealthCheckManager() *HealthCheckManager {
	return &HealthCheckManager{
		checkers: make(map[string]*transport.HealthChecker),
		configs:  make(map[string]*TransportHealthCheckConfig),
	}
}

// GetOrCreateHealthChecker gets an existing health checker or creates a new one
// key should be the origin URL (e.g., "https://api.example.com") or origin ID
func (m *HealthCheckManager) GetOrCreateHealthChecker(key string, targetURL string, cfg *TransportHealthCheckConfig) (*transport.HealthChecker, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if we already have a health checker for this key
	if checker, exists := m.checkers[key]; exists {
		// Update config if it changed
		if m.configs[key] != cfg {
			m.configs[key] = cfg
			// Restart health checker with new config
			checker.Stop()
			newChecker := m.createHealthChecker(targetURL, cfg)
			if newChecker != nil {
				newChecker.Start()
				m.checkers[key] = newChecker
			}
			return newChecker, nil
		}
		return checker, nil
	}

	// Create new health checker
	checker := m.createHealthChecker(targetURL, cfg)
	if checker != nil {
		checker.Start()
		m.checkers[key] = checker
		m.configs[key] = cfg
		slog.Info("created health checker for origin",
			"key", key,
			"target", targetURL,
			"type", cfg.Type,
			"endpoint", cfg.Endpoint)
	}

	return checker, nil
}

// createHealthChecker creates a health checker from config
func (m *HealthCheckManager) createHealthChecker(targetURL string, cfg *TransportHealthCheckConfig) *transport.HealthChecker {
	// Parse target URL to extract host
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		slog.Warn("failed to parse target URL for health check",
			"url", targetURL,
			"error", err)
		return nil
	}

	// Determine health check type
	var healthCheckType transport.HealthCheckType
	switch cfg.Type {
	case "https":
		healthCheckType = transport.HealthCheckHTTPS
	case "tcp":
		healthCheckType = transport.HealthCheckTCP
	case "http", "":
		healthCheckType = transport.HealthCheckHTTP
	default:
		slog.Warn("unknown health check type, defaulting to http",
			"type", cfg.Type)
		healthCheckType = transport.HealthCheckHTTP
	}

	// Set defaults
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "/health"
	}
	interval := cfg.Interval.Duration
	if interval == 0 {
		interval = 30 * time.Second
	}
	timeout := cfg.Timeout.Duration
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	healthyThreshold := cfg.HealthyThreshold
	if healthyThreshold == 0 {
		healthyThreshold = 2
	}
	unhealthyThreshold := cfg.UnhealthyThreshold
	if unhealthyThreshold == 0 {
		unhealthyThreshold = 3
	}
	expectedStatus := cfg.ExpectedStatus
	if expectedStatus == 0 {
		expectedStatus = 200
	}

	// For TCP checks, use host:port as target
	target := parsedURL.Host
	if healthCheckType == transport.HealthCheckTCP {
		if parsedURL.Port() == "" {
			// Add default port based on scheme
			if parsedURL.Scheme == "https" {
				target = fmt.Sprintf("%s:443", parsedURL.Hostname())
			} else {
				target = fmt.Sprintf("%s:80", parsedURL.Hostname())
			}
		}
	}

	// Convert config to transport.HealthCheckConfig
	transportConfig := &transport.HealthCheckConfig{
		Type:               healthCheckType,
		Endpoint:           endpoint,
		Host:               cfg.Host,
		Interval:           interval,
		Timeout:            timeout,
		HealthyThreshold:   healthyThreshold,
		UnhealthyThreshold: unhealthyThreshold,
		ExpectedStatus:     expectedStatus,
		ExpectedBody:       cfg.ExpectedBody,
	}

	return transport.NewHealthChecker(target, transportConfig)
}

// GetHealthChecker gets an existing health checker without creating one
func (m *HealthCheckManager) GetHealthChecker(key string) *transport.HealthChecker {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.checkers[key]
}

// RemoveHealthChecker removes and stops a health checker
func (m *HealthCheckManager) RemoveHealthChecker(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if checker, exists := m.checkers[key]; exists {
		checker.Stop()
		delete(m.checkers, key)
		delete(m.configs, key)
		slog.Info("removed health checker for origin", "key", key)
	}
}

// StopAll stops all health checkers
func (m *HealthCheckManager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for key, checker := range m.checkers {
		checker.Stop()
		slog.Debug("stopped health checker", "key", key)
	}

	m.checkers = make(map[string]*transport.HealthChecker)
	m.configs = make(map[string]*TransportHealthCheckConfig)
}

