// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	cacher "github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/observe/events"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

const (
	healthCheckDefaultInterval = 60 * time.Second
	healthCheckDefaultTimeout  = 10 * time.Second
	healthCheckDefaultModel    = "gpt-4o-mini"
	healthCheckLockType        = "ai-health-lock"
	healthCheckResultType      = "ai-health-result"
	healthCheckJitterPercent   = 10
)

// HealthCheckConfig configures proactive health checking for a provider.
type HealthCheckConfig struct {
	Enabled  bool            `json:"enabled"`
	Interval reqctx.Duration `json:"interval"`
	Model    string          `json:"model"`
	Timeout  reqctx.Duration `json:"timeout"`
}

// HealthChecker performs proactive health checks against AI providers with
// distributed leader election via Redis. When multiple proxy instances run,
// only one acquires the lock per provider per interval. Others read the
// shared result. When Redis is unavailable, every instance checks independently.
type HealthChecker struct {
	tracker     *ProviderTracker
	router      *Router
	providers   []*ProviderConfig
	cache       cacher.Cacher
	instanceID  string
	httpChecker HealthCheckFn

	mu              sync.Mutex
	failingSince    map[string]time.Time // provider name -> first failure time
	consecutiveFail map[string]int       // provider name -> consecutive failure count
}

// HealthCheckFn sends a lightweight probe request to a provider and returns an error on failure.
type HealthCheckFn func(ctx context.Context, provider *ProviderConfig, model string) error

// NewHealthChecker creates a new HealthChecker. The cache parameter may be nil,
// in which case distributed locking is disabled and every instance checks independently.
func NewHealthChecker(
	tracker *ProviderTracker,
	router *Router,
	providers []*ProviderConfig,
	cache cacher.Cacher,
	instanceID string,
	checkFn HealthCheckFn,
) *HealthChecker {
	return &HealthChecker{
		tracker:         tracker,
		router:          router,
		providers:       providers,
		cache:           cache,
		instanceID:      instanceID,
		httpChecker:     checkFn,
		failingSince:    make(map[string]time.Time),
		consecutiveFail: make(map[string]int),
	}
}

// Start launches background health-check goroutines for each provider with
// health_check.enabled. It returns immediately. Cancel the context to stop all goroutines.
func (hc *HealthChecker) Start(ctx context.Context) {
	for _, p := range hc.providers {
		if p.HealthCheck == nil || !p.HealthCheck.Enabled {
			continue
		}
		go hc.runProvider(ctx, p)
	}
}

func (hc *HealthChecker) runProvider(ctx context.Context, p *ProviderConfig) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("health checker panic recovered", "provider", p.Name, "panic", r)
		}
	}()

	interval := healthCheckDefaultInterval
	if p.HealthCheck.Interval.Duration > 0 {
		interval = p.HealthCheck.Interval.Duration
	}

	// Initial jitter: random 0-10% of interval to prevent thundering herd on startup.
	jitter := time.Duration(rand.Int64N(int64(interval) * healthCheckJitterPercent / 100))
	select {
	case <-ctx.Done():
		return
	case <-time.After(jitter):
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run first check immediately after jitter.
	hc.checkProvider(ctx, p)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			hc.checkProvider(ctx, p)
		}
	}
}

func (hc *HealthChecker) checkProvider(ctx context.Context, p *ProviderConfig) {
	interval := healthCheckDefaultInterval
	if p.HealthCheck.Interval.Duration > 0 {
		interval = p.HealthCheck.Interval.Duration
	}

	model := healthCheckDefaultModel
	if p.HealthCheck.Model != "" {
		model = p.HealthCheck.Model
	}

	timeout := healthCheckDefaultTimeout
	if p.HealthCheck.Timeout.Duration > 0 {
		timeout = p.HealthCheck.Timeout.Duration
	}

	lockKey := "lock:" + p.Name
	resultKey := "result:" + p.Name

	// Try distributed lock if cache is available.
	if hc.cache != nil {
		acquired := hc.tryAcquireLock(ctx, lockKey, interval)
		if !acquired {
			// Another instance owns this check. Read its result.
			hc.readSharedResult(ctx, p, resultKey)
			return
		}
	}

	// We are the leader (or no cache). Execute the actual health check.
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var checkErr error
	if hc.httpChecker != nil {
		checkErr = hc.httpChecker(checkCtx, p, model)
	}

	if checkErr != nil {
		hc.handleFailure(ctx, p)
		hc.writeSharedResult(ctx, resultKey, "unhealthy:"+checkErr.Error(), interval)
	} else {
		hc.handleSuccess(ctx, p)
		hc.writeSharedResult(ctx, resultKey, "healthy", interval)
	}
}

// tryAcquireLock attempts a SETNX-style lock via PutWithExpires.
// It writes the instance ID with a TTL equal to the check interval.
// Returns true if this instance should perform the check.
func (hc *HealthChecker) tryAcquireLock(ctx context.Context, lockKey string, ttl time.Duration) bool {
	if hc.cache == nil {
		return true
	}

	// Check if lock already exists.
	reader, err := hc.cache.Get(ctx, healthCheckLockType, lockKey)
	if err == nil {
		// Lock exists. Read the holder.
		data, readErr := io.ReadAll(reader)
		if readErr == nil && string(data) != "" {
			// Lock held by someone (possibly us from a previous round, but that is fine).
			return false
		}
	}

	// Lock does not exist or read failed. Try to claim it.
	err = hc.cache.PutWithExpires(ctx, healthCheckLockType, lockKey,
		bytes.NewReader([]byte(hc.instanceID)), ttl)
	if err != nil {
		slog.Debug("health check lock acquisition failed, checking independently",
			"provider", lockKey, "error", err)
		return true // Fallback: check independently.
	}

	// Verify we actually wrote it (best effort, not truly atomic without Redis SETNX).
	reader, err = hc.cache.Get(ctx, healthCheckLockType, lockKey)
	if err != nil {
		return true // Cannot verify, check independently.
	}
	data, _ := io.ReadAll(reader)
	return string(data) == hc.instanceID
}

func (hc *HealthChecker) readSharedResult(ctx context.Context, p *ProviderConfig, resultKey string) {
	if hc.cache == nil {
		return
	}

	reader, err := hc.cache.Get(ctx, healthCheckResultType, resultKey)
	if err != nil {
		return // No result available yet, nothing to act on.
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return
	}

	result := string(data)
	if strings.HasPrefix(result, "unhealthy:") {
		hc.handleFailure(ctx, p)
	} else if result == "healthy" {
		hc.handleSuccess(ctx, p)
	}
}

func (hc *HealthChecker) writeSharedResult(ctx context.Context, resultKey string, result string, ttl time.Duration) {
	if hc.cache == nil {
		return
	}

	err := hc.cache.PutWithExpires(ctx, healthCheckResultType, resultKey,
		bytes.NewReader([]byte(result)), ttl)
	if err != nil {
		slog.Debug("failed to write health check result", "key", resultKey, "error", err)
	}
}

func (hc *HealthChecker) handleFailure(ctx context.Context, p *ProviderConfig) {
	hc.mu.Lock()
	hc.consecutiveFail[p.Name]++
	count := hc.consecutiveFail[p.Name]
	if _, exists := hc.failingSince[p.Name]; !exists {
		hc.failingSince[p.Name] = time.Now()
	}
	hc.mu.Unlock()

	hc.tracker.RecordError(p.Name)

	if hc.router != nil {
		hc.router.MarkHealthy(p.Name, false)
	}

	circuitState := hc.tracker.CircuitState(p.Name)

	slog.Warn("health check failed",
		"provider", p.Name,
		"consecutive_failures", count,
		"circuit_state", circuitState)

	events.Emit(ctx, "system",
		events.NewAIHealthCheckFailed("system", "", p.Name,
			fmt.Sprintf("health check failed (attempt %d)", count),
			count, circuitState))
}

func (hc *HealthChecker) handleSuccess(ctx context.Context, p *ProviderConfig) {
	hc.mu.Lock()
	wasFailing := hc.consecutiveFail[p.Name] > 0
	var downtimeMs int64
	if failStart, ok := hc.failingSince[p.Name]; ok && wasFailing {
		downtimeMs = time.Since(failStart).Milliseconds()
	}
	hc.consecutiveFail[p.Name] = 0
	delete(hc.failingSince, p.Name)
	hc.mu.Unlock()

	hc.tracker.RecordSuccess(p.Name, 0)

	if hc.router != nil {
		hc.router.MarkHealthy(p.Name, true)
	}

	if wasFailing {
		slog.Info("health check recovered", "provider", p.Name, "downtime_ms", downtimeMs)

		events.Emit(ctx, "system",
			events.NewAIHealthCheckRecovered("system", "", p.Name, downtimeMs))
	}
}

// ConsecutiveFailures returns the current consecutive failure count for a provider.
// This is primarily useful for testing.
func (hc *HealthChecker) ConsecutiveFailures(name string) int {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	return hc.consecutiveFail[name]
}
