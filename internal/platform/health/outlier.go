// Package health implements health check endpoints and upstream health monitoring.
package health

import (
	"sync"
	"time"
)

// OutlierConfig configures outlier detection and ejection.
type OutlierConfig struct {
	ConsecutiveFailures int           `json:"consecutive_failures" yaml:"consecutive_failures"`
	EjectionDuration    time.Duration `json:"ejection_duration" yaml:"ejection_duration"`
	MaxEjectedPercent   float64       `json:"max_ejected_percent" yaml:"max_ejected_percent"` // 0.0-1.0
	CheckInterval       time.Duration `json:"check_interval" yaml:"check_interval"`
}

// OutlierDetector tracks upstream health and ejects unhealthy hosts.
// An ejected host is temporarily removed from the healthy pool.
type OutlierDetector struct {
	mu     sync.RWMutex
	config OutlierConfig
	hosts  map[string]*hostState
}

// hostState tracks per-host failure and ejection state.
type hostState struct {
	consecutiveFailures int
	ejected             bool
	ejectedAt           time.Time
	totalRequests       int64
	totalFailures       int64
}

// NewOutlierDetector creates an OutlierDetector with the given config.
// Sensible defaults are applied for zero-value fields.
func NewOutlierDetector(cfg OutlierConfig) *OutlierDetector {
	if cfg.ConsecutiveFailures <= 0 {
		cfg.ConsecutiveFailures = 5
	}
	if cfg.EjectionDuration <= 0 {
		cfg.EjectionDuration = 30 * time.Second
	}
	if cfg.MaxEjectedPercent <= 0 {
		cfg.MaxEjectedPercent = 0.5
	}
	if cfg.MaxEjectedPercent > 1.0 {
		cfg.MaxEjectedPercent = 1.0
	}
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = 10 * time.Second
	}
	return &OutlierDetector{
		config: cfg,
		hosts:  make(map[string]*hostState),
	}
}

// getOrCreate returns the hostState for the given host, creating it if needed.
// Caller must hold od.mu (write lock).
func (od *OutlierDetector) getOrCreate(host string) *hostState {
	hs, ok := od.hosts[host]
	if !ok {
		hs = &hostState{}
		od.hosts[host] = hs
	}
	return hs
}

// RecordSuccess records a successful request to the given host. On success,
// the consecutive failure counter is reset.
func (od *OutlierDetector) RecordSuccess(host string) {
	od.mu.Lock()
	defer od.mu.Unlock()

	hs := od.getOrCreate(host)
	hs.totalRequests++
	hs.consecutiveFailures = 0
}

// RecordFailure records a failed request to the given host. If the consecutive
// failure count reaches the threshold, the host is ejected (provided the
// max ejected percentage is not exceeded).
func (od *OutlierDetector) RecordFailure(host string) {
	od.mu.Lock()
	defer od.mu.Unlock()

	hs := od.getOrCreate(host)
	hs.totalRequests++
	hs.totalFailures++
	hs.consecutiveFailures++

	if hs.consecutiveFailures >= od.config.ConsecutiveFailures && !hs.ejected {
		// Check max ejected percentage before ejecting
		if od.canEject() {
			hs.ejected = true
			hs.ejectedAt = time.Now()
		}
	}
}

// canEject returns true if ejecting one more host would not exceed the
// MaxEjectedPercent threshold. Caller must hold od.mu.
func (od *OutlierDetector) canEject() bool {
	total := len(od.hosts)
	if total <= 1 {
		// Never eject the last host
		return false
	}

	ejected := 0
	for _, hs := range od.hosts {
		if hs.ejected {
			ejected++
		}
	}

	// Adding one more ejection
	newEjected := ejected + 1
	return float64(newEjected)/float64(total) <= od.config.MaxEjectedPercent
}

// IsEjected returns true if the host is currently ejected.
func (od *OutlierDetector) IsEjected(host string) bool {
	od.mu.RLock()
	defer od.mu.RUnlock()

	hs, ok := od.hosts[host]
	if !ok {
		return false
	}
	return hs.ejected
}

// CheckRecovery checks all ejected hosts and un-ejects those whose ejection
// duration has elapsed. This should be called periodically (e.g., on a ticker
// at CheckInterval).
func (od *OutlierDetector) CheckRecovery() {
	od.mu.Lock()
	defer od.mu.Unlock()

	now := time.Now()
	for _, hs := range od.hosts {
		if hs.ejected && now.Sub(hs.ejectedAt) >= od.config.EjectionDuration {
			hs.ejected = false
			hs.consecutiveFailures = 0
		}
	}
}

// HostStats holds exported statistics for a single host.
type HostStats struct {
	ConsecutiveFailures int   `json:"consecutive_failures"`
	Ejected             bool  `json:"ejected"`
	TotalRequests       int64 `json:"total_requests"`
	TotalFailures       int64 `json:"total_failures"`
}

// Stats returns a snapshot of all tracked hosts and their state.
func (od *OutlierDetector) Stats() map[string]HostStats {
	od.mu.RLock()
	defer od.mu.RUnlock()

	result := make(map[string]HostStats, len(od.hosts))
	for host, hs := range od.hosts {
		result[host] = HostStats{
			ConsecutiveFailures: hs.consecutiveFailures,
			Ejected:             hs.ejected,
			TotalRequests:       hs.totalRequests,
			TotalFailures:       hs.totalFailures,
		}
	}
	return result
}
