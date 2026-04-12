// Package health implements health check endpoints and upstream health monitoring.
package health

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/soapbucket/sbproxy/internal/version"
)

// Status represents the health status of the service
type Status struct {
	Status    string            `json:"status"`            // "ok", "degraded", or "error"
	Timestamp string            `json:"timestamp"`         // ISO 8601 timestamp
	Version   string            `json:"version"`           // Application version
	BuildHash string            `json:"build_hash"`        // Build hash
	Uptime    string            `json:"uptime"`            // Human-readable uptime
	Checks    map[string]string `json:"checks,omitempty"`  // Component-specific health checks
	Details   map[string]any    `json:"details,omitempty"` // Additional details
}

// Checker is a component that can report its health status
type Checker interface {
	// Name returns the name of the component
	Name() string
	// Check returns the health status and any error
	Check() (string, error)
}

// Manager manages health checks for the service
type Manager struct {
	mu             sync.RWMutex
	checkers       map[string]Checker
	ready          atomic.Bool
	live           atomic.Bool
	shuttingDown   atomic.Bool
	inflightCount  atomic.Int64
	startTime      time.Time

	// Cached dependency status to avoid per-request overhead.
	depCacheMu     sync.RWMutex
	depCacheResult map[string]string
	depCacheTime   time.Time

	// Grace period for readiness checks. During the startup grace period,
	// readiness checks based on dependency status will not fail.
	startupGrace time.Duration
}

var (
	globalManager *Manager
	once          sync.Once
)

const (
	// depCacheTTL is how long cached dependency check results are valid.
	depCacheTTL = 5 * time.Second

	// defaultStartupGrace is the grace period during which readiness checks
	// will not fail due to dependency issues (allows time for init).
	defaultStartupGrace = 30 * time.Second
)

// Initialize initializes the global health manager
func Initialize() *Manager {
	once.Do(func() {
		globalManager = &Manager{
			checkers:     make(map[string]Checker),
			startTime:    time.Now(),
			startupGrace: defaultStartupGrace,
		}
		// Service starts as live but not ready
		globalManager.live.Store(true)
		globalManager.ready.Store(false)
	})
	return globalManager
}

// GetManager returns the global health manager
func GetManager() *Manager {
	if globalManager == nil {
		return Initialize()
	}
	return globalManager
}

// RegisterChecker registers a health checker
func (m *Manager) RegisterChecker(checker Checker) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checkers[checker.Name()] = checker
	slog.Debug("registered health checker", "checker", checker.Name())
}

// SetReady marks the service as ready to accept traffic
func (m *Manager) SetReady(ready bool) {
	m.ready.Store(ready)
	slog.Info("service readiness changed", "ready", ready)
}

// SetLive marks the service as alive
func (m *Manager) SetLive(live bool) {
	m.live.Store(live)
	slog.Info("service liveness changed", "live", live)
}

// IsReady returns whether the service is ready to accept traffic
func (m *Manager) IsReady() bool {
	return m.ready.Load()
}

// IsLive returns whether the service is alive
func (m *Manager) IsLive() bool {
	return m.live.Load()
}

// SetShuttingDown marks the service as shutting down
func (m *Manager) SetShuttingDown(shuttingDown bool) {
	m.shuttingDown.Store(shuttingDown)
	slog.Info("service shutdown state changed", "shutting_down", shuttingDown)
}

// IsShuttingDown returns whether the service is shutting down
func (m *Manager) IsShuttingDown() bool {
	return m.shuttingDown.Load()
}

// IncrementInflight increments the in-flight request counter
func (m *Manager) IncrementInflight() {
	count := m.inflightCount.Add(1)
	slog.Debug("incremented in-flight request count", "count", count)
}

// DecrementInflight decrements the in-flight request counter
func (m *Manager) DecrementInflight() {
	count := m.inflightCount.Add(-1)
	slog.Debug("decremented in-flight request count", "count", count)
}

// GetInflightCount returns the current number of in-flight requests
func (m *Manager) GetInflightCount() int64 {
	return m.inflightCount.Load()
}

// GetStatus returns the current health status
func (m *Manager) GetStatus() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := Status{
		Status:    "ok",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Version:   version.String(),
		BuildHash: version.BuildHash,
		Uptime:    time.Since(m.startTime).Round(time.Second).String(),
		Checks:    make(map[string]string),
		Details:   make(map[string]any),
	}

	// Add shutdown and in-flight request information
	if m.IsShuttingDown() {
		status.Details["shutting_down"] = true
		status.Details["inflight_requests"] = m.GetInflightCount()
	}

	// Run all health checks
	hasError := false
	hasDegraded := false
	for name, checker := range m.checkers {
		checkStatus, err := checker.Check()
		if err != nil {
			status.Checks[name] = "error: " + err.Error()
			hasError = true
		} else {
			status.Checks[name] = checkStatus
			if checkStatus != "ok" {
				hasDegraded = true
			}
		}
	}

	// Determine overall status
	if m.IsShuttingDown() {
		status.Status = "shutting_down"
	} else if hasError {
		status.Status = "error"
	} else if hasDegraded {
		status.Status = "degraded"
	}

	return status
}

// HealthHandler returns an HTTP handler for the /health endpoint
func (m *Manager) HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := m.GetStatus()

		w.Header().Set("Content-Type", "application/json")

		// Set HTTP status code based on health status
		httpStatus := http.StatusOK
		if status.Status == "error" {
			httpStatus = http.StatusServiceUnavailable
		} else if status.Status == "degraded" {
			httpStatus = http.StatusOK // 200 for degraded but still functional
		}

		w.WriteHeader(httpStatus)

		if err := json.NewEncoder(w).Encode(status); err != nil {
			slog.Error("failed to encode health status", "error", err)
		}

		slog.Debug("health check",
			"status", status.Status,
			"http_status", httpStatus,
			"remote_addr", r.RemoteAddr)
	}
}

// ReadyHandler returns an HTTP handler for the /ready endpoint (Kubernetes readiness probe)
func (m *Manager) ReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If shutting down, immediately return not ready
		if m.IsShuttingDown() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":            "not_ready",
				"reason":            "shutting_down",
				"inflight_requests": m.GetInflightCount(),
				"timestamp":         time.Now().UTC().Format(time.RFC3339),
			})
			slog.Debug("readiness check - shutting down",
				"shutting_down", true,
				"inflight_requests", m.GetInflightCount(),
				"remote_addr", r.RemoteAddr)
			return
		}

		ready := m.IsReady()

		w.Header().Set("Content-Type", "application/json")

		if ready {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":    "ready",
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			})
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":    "not_ready",
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			})
		}

		slog.Debug("readiness check",
			"ready", ready,
			"remote_addr", r.RemoteAddr)
	}
}

// LiveHandler returns an HTTP handler for the /live endpoint (Kubernetes liveness probe)
func (m *Manager) LiveHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		live := m.IsLive()

		w.Header().Set("Content-Type", "application/json")

		if live {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":    "alive",
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			})
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":    "dead",
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			})
		}

		slog.Debug("liveness check",
			"live", live,
			"remote_addr", r.RemoteAddr)
	}
}

// getDependencyStatus returns cached dependency check results. Results are
// cached for depCacheTTL (5 seconds) to avoid running checks on every request.
func (m *Manager) getDependencyStatus() map[string]string {
	m.depCacheMu.RLock()
	if m.depCacheResult != nil && time.Since(m.depCacheTime) < depCacheTTL {
		result := make(map[string]string, len(m.depCacheResult))
		for k, v := range m.depCacheResult {
			result[k] = v
		}
		m.depCacheMu.RUnlock()
		return result
	}
	m.depCacheMu.RUnlock()

	// Cache miss or expired. Run checks.
	m.mu.RLock()
	deps := make(map[string]string, len(m.checkers))
	for name, checker := range m.checkers {
		checkStatus, err := checker.Check()
		if err != nil {
			deps[name] = "error"
		} else {
			deps[name] = checkStatus
		}
	}
	m.mu.RUnlock()

	m.depCacheMu.Lock()
	m.depCacheResult = deps
	m.depCacheTime = time.Now()
	m.depCacheMu.Unlock()

	// Return a copy so callers cannot mutate the cache.
	result := make(map[string]string, len(deps))
	for k, v := range deps {
		result[k] = v
	}
	return result
}

// inStartupGrace returns true if the service is still within the startup
// grace period, during which dependency failures should not cause readiness
// to fail.
func (m *Manager) inStartupGrace() bool {
	return time.Since(m.startTime) < m.startupGrace
}

// HealthzHandler returns an HTTP handler for the /healthz endpoint.
// It includes dependency status with cached results.
func (m *Manager) HealthzHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		deps := m.getDependencyStatus()

		overallStatus := "ok"
		for _, v := range deps {
			if v == "error" {
				overallStatus = "error"
				break
			}
			if v != "ok" {
				overallStatus = "degraded"
			}
		}

		if m.IsShuttingDown() {
			overallStatus = "shutting_down"
		}

		w.Header().Set("Content-Type", "application/json")
		if overallStatus == "error" {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":       overallStatus,
			"dependencies": deps,
		})

		slog.Debug("healthz check",
			"status", overallStatus,
			"remote_addr", r.RemoteAddr)
	}
}

// ReadyzHandler returns an HTTP handler for the /readyz endpoint.
// Returns 503 if any critical dependency (config, cache) is unreachable,
// unless the service is still in its startup grace period.
// Returns 200 with {"ready": true} otherwise.
func (m *Manager) ReadyzHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// If shutting down, always not ready.
		if m.IsShuttingDown() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ready":  false,
				"reason": "shutting_down",
			})
			slog.Debug("readyz check - shutting down", "remote_addr", r.RemoteAddr)
			return
		}

		// Check dependencies for failures.
		deps := m.getDependencyStatus()
		hasFailure := false
		failedDeps := make(map[string]string)
		for name, status := range deps {
			if status == "error" {
				hasFailure = true
				failedDeps[name] = status
			}
		}

		// During startup grace period, ignore dependency failures.
		if hasFailure && !m.inStartupGrace() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ready":       false,
				"reason":      "dependency_failure",
				"failed_deps": failedDeps,
			})
			slog.Debug("readyz check - dependency failure",
				"failed_deps", failedDeps,
				"remote_addr", r.RemoteAddr)
			return
		}

		// Also check the manager's ready flag (set by the application).
		if !m.IsReady() && !m.inStartupGrace() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ready":  false,
				"reason": "not_ready",
			})
			slog.Debug("readyz check - not ready", "remote_addr", r.RemoteAddr)
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ready": true,
		})
		slog.Debug("readyz check - ready", "remote_addr", r.RemoteAddr)
	}
}

// LivezHandler returns an HTTP handler for the /livez endpoint.
// Always returns 200 with {"alive": true} as long as the process is running.
// This is intended for K8s liveness probes and should never fail unless the
// process is hung.
func (m *Manager) LivezHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"alive": true,
		})
		slog.Debug("livez check", "remote_addr", r.RemoteAddr)
	}
}
