// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"crypto/rand"
	"encoding/binary"
	"log/slog"
	mathrand "math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

// CanaryConfig defines a canary experiment for gradually shifting traffic
// from a control config to an experiment config based on metrics.
type CanaryConfig struct {
	Enabled         bool          `json:"enabled"`
	Name            string        `json:"name"`
	Control         CanaryVariant `json:"control"`
	Experiment      CanaryVariant `json:"experiment"`
	TrafficPercent  float64       `json:"traffic_percent"`         // Initial % to experiment (e.g., 5.0)
	RampSteps       []float64     `json:"ramp_steps,omitempty"`    // Auto-ramp percentages (e.g., [5, 10, 25, 50, 100])
	RampInterval    time.Duration `json:"ramp_interval,omitempty"` // Time between ramp steps
	MaxErrorRate    float64       `json:"max_error_rate"`          // Rollback if experiment error rate exceeds this
	MaxLatencyRatio float64       `json:"max_latency_ratio"`       // Rollback if experiment latency > control * ratio
	MinRequests     int64         `json:"min_requests"`            // Min requests before evaluating
	EvalInterval    time.Duration `json:"eval_interval"`           // How often to evaluate metrics
}

// CanaryVariant represents one side of a canary experiment (control or experiment).
type CanaryVariant struct {
	Name     string         `json:"name"`
	Provider string         `json:"provider,omitempty"`
	Model    string         `json:"model,omitempty"`
	Config   map[string]any `json:"config,omitempty"` // Additional config overrides
}

// CanaryStatus tracks the state of a canary experiment.
type CanaryStatus string

const (
	CanaryStatusRunning    CanaryStatus = "running"
	CanaryStatusPromoted   CanaryStatus = "promoted"
	CanaryStatusRolledBack CanaryStatus = "rolled_back"
	CanaryStatusPaused     CanaryStatus = "paused"
)

// CanaryExperiment manages a running canary experiment, routing traffic between
// a control and experiment variant while tracking metrics for auto-evaluation.
type CanaryExperiment struct {
	config     CanaryConfig
	status     CanaryStatus
	currentPct float64 // Current traffic percentage to experiment (0-100)
	rampIdx    int     // Current index in ramp_steps
	control    *CanaryMetrics
	experiment *CanaryMetrics
	startedAt  time.Time
	mu         sync.RWMutex
	rng        *mathrand.Rand
	rngMu      sync.Mutex
	evalDone   chan struct{}
}

// CanaryMetrics tracks per-variant performance counters using atomics for
// lock-free concurrent updates.
type CanaryMetrics struct {
	Requests     atomic.Int64
	Errors       atomic.Int64
	TotalLatency atomic.Int64 // Microseconds
	TotalTokens  atomic.Int64
	MinLatency   atomic.Int64
	MaxLatency   atomic.Int64
}

// CanaryMetricsSnapshot is a point-in-time view of a variant's metrics.
type CanaryMetricsSnapshot struct {
	Requests     int64   `json:"requests"`
	Errors       int64   `json:"errors"`
	ErrorRate    float64 `json:"error_rate"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
	TotalTokens  int64   `json:"total_tokens"`
}

// NewCanaryExperiment creates a new canary experiment with the given config.
// The experiment starts in running status with the configured initial traffic percentage.
func NewCanaryExperiment(config CanaryConfig) *CanaryExperiment {
	var seed [8]byte
	_, _ = rand.Read(seed[:])
	src := mathrand.NewPCG(binary.LittleEndian.Uint64(seed[:]), 0)

	initialPct := config.TrafficPercent
	if len(config.RampSteps) > 0 {
		initialPct = config.RampSteps[0]
	}

	control := &CanaryMetrics{}
	experiment := &CanaryMetrics{}
	// Initialize min latency to a high value so any real latency is lower.
	control.MinLatency.Store(1<<63 - 1)
	experiment.MinLatency.Store(1<<63 - 1)

	return &CanaryExperiment{
		config:     config,
		status:     CanaryStatusRunning,
		currentPct: initialPct,
		rampIdx:    0,
		control:    control,
		experiment: experiment,
		startedAt:  time.Now(),
		rng:        mathrand.New(src),
		evalDone:   make(chan struct{}),
	}
}

// Route decides whether to use control or experiment for this request.
// Returns the variant name and the variant config.
func (ce *CanaryExperiment) Route() (variant string, v *CanaryVariant) {
	ce.mu.RLock()
	status := ce.status
	pct := ce.currentPct
	ce.mu.RUnlock()

	// If not running, always route to control (rolled back) or experiment (promoted).
	if status == CanaryStatusPromoted {
		return ce.config.Experiment.Name, &ce.config.Experiment
	}
	if status != CanaryStatusRunning {
		return ce.config.Control.Name, &ce.config.Control
	}

	// Route based on current traffic percentage.
	ce.rngMu.Lock()
	roll := ce.rng.Float64() * 100.0
	ce.rngMu.Unlock()

	if roll < pct {
		return ce.config.Experiment.Name, &ce.config.Experiment
	}
	return ce.config.Control.Name, &ce.config.Control
}

// RecordResult records metrics for a variant after a request completes.
func (ce *CanaryExperiment) RecordResult(variant string, latency time.Duration, tokens int, err error) {
	var m *CanaryMetrics
	if variant == ce.config.Experiment.Name {
		m = ce.experiment
	} else {
		m = ce.control
	}

	m.Requests.Add(1)
	if err != nil {
		m.Errors.Add(1)
	}

	latUs := latency.Microseconds()
	m.TotalLatency.Add(latUs)
	m.TotalTokens.Add(int64(tokens))

	// Update min latency (CAS loop).
	for {
		cur := m.MinLatency.Load()
		if latUs >= cur {
			break
		}
		if m.MinLatency.CompareAndSwap(cur, latUs) {
			break
		}
	}

	// Update max latency (CAS loop).
	for {
		cur := m.MaxLatency.Load()
		if latUs <= cur {
			break
		}
		if m.MaxLatency.CompareAndSwap(cur, latUs) {
			break
		}
	}
}

// Evaluate checks if the experiment should be promoted or rolled back based
// on the configured success criteria. Returns the resulting status.
//
// Logic:
//  1. If experiment requests < MinRequests, skip evaluation (keep running).
//  2. If experiment error rate > MaxErrorRate, rollback.
//  3. If experiment avg latency > control avg latency * MaxLatencyRatio, rollback.
//  4. If all checks pass and ramp steps remain, advance to next step.
//  5. If all ramp steps completed (100%), promote.
func (ce *CanaryExperiment) Evaluate() CanaryStatus {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	if ce.status != CanaryStatusRunning {
		return ce.status
	}

	expReqs := ce.experiment.Requests.Load()
	if expReqs < ce.config.MinRequests {
		return CanaryStatusRunning
	}

	expErrors := ce.experiment.Errors.Load()
	expErrorRate := float64(expErrors) / float64(expReqs)

	// Check error rate threshold.
	if ce.config.MaxErrorRate > 0 && expErrorRate > ce.config.MaxErrorRate {
		slog.Info("canary rollback: experiment error rate exceeded threshold",
			"name", ce.config.Name,
			"error_rate", expErrorRate,
			"threshold", ce.config.MaxErrorRate,
		)
		ce.status = CanaryStatusRolledBack
		ce.currentPct = 0
		return ce.status
	}

	// Check latency ratio threshold.
	if ce.config.MaxLatencyRatio > 0 {
		ctrlReqs := ce.control.Requests.Load()
		if ctrlReqs > 0 {
			ctrlAvgLat := float64(ce.control.TotalLatency.Load()) / float64(ctrlReqs)
			expAvgLat := float64(ce.experiment.TotalLatency.Load()) / float64(expReqs)
			if ctrlAvgLat > 0 && expAvgLat > ctrlAvgLat*ce.config.MaxLatencyRatio {
				slog.Info("canary rollback: experiment latency exceeded threshold",
					"name", ce.config.Name,
					"experiment_avg_us", expAvgLat,
					"control_avg_us", ctrlAvgLat,
					"ratio", expAvgLat/ctrlAvgLat,
					"threshold", ce.config.MaxLatencyRatio,
				)
				ce.status = CanaryStatusRolledBack
				ce.currentPct = 0
				return ce.status
			}
		}
	}

	// All checks passed. Advance ramp if steps are configured.
	if len(ce.config.RampSteps) > 0 {
		nextIdx := ce.rampIdx + 1
		if nextIdx < len(ce.config.RampSteps) {
			ce.rampIdx = nextIdx
			ce.currentPct = ce.config.RampSteps[nextIdx]
			slog.Info("canary ramp advanced",
				"name", ce.config.Name,
				"step", nextIdx,
				"traffic_percent", ce.currentPct,
			)
			return CanaryStatusRunning
		}
		// All steps completed (last step should be 100).
		ce.status = CanaryStatusPromoted
		ce.currentPct = 100
		return ce.status
	}

	// No ramp steps, just promote if metrics are good.
	ce.status = CanaryStatusPromoted
	ce.currentPct = 100
	return ce.status
}

// StartAutoEval starts periodic evaluation in a background goroutine.
// The goroutine exits when Stop is called.
func (ce *CanaryExperiment) StartAutoEval() {
	interval := ce.config.EvalInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				status := ce.Evaluate()
				if status != CanaryStatusRunning {
					return
				}
			case <-ce.evalDone:
				return
			}
		}
	}()
}

// Stop stops the background evaluation goroutine.
func (ce *CanaryExperiment) Stop() {
	select {
	case <-ce.evalDone:
		// Already closed.
	default:
		close(ce.evalDone)
	}
}

// Status returns the current experiment status.
func (ce *CanaryExperiment) Status() CanaryStatus {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	return ce.status
}

// CurrentTrafficPercent returns the current percentage of traffic going to the experiment.
func (ce *CanaryExperiment) CurrentTrafficPercent() float64 {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	return ce.currentPct
}

// Metrics returns a snapshot of both control and experiment metrics.
func (ce *CanaryExperiment) Metrics() (control, experiment *CanaryMetricsSnapshot) {
	return metricsSnapshot(ce.control), metricsSnapshot(ce.experiment)
}

func metricsSnapshot(m *CanaryMetrics) *CanaryMetricsSnapshot {
	reqs := m.Requests.Load()
	errs := m.Errors.Load()
	totalLat := m.TotalLatency.Load()

	var errorRate float64
	var avgLatMs float64
	if reqs > 0 {
		errorRate = float64(errs) / float64(reqs)
		avgLatMs = float64(totalLat) / float64(reqs) / 1000.0 // Microseconds to milliseconds
	}

	return &CanaryMetricsSnapshot{
		Requests:     reqs,
		Errors:       errs,
		ErrorRate:    errorRate,
		AvgLatencyMs: avgLatMs,
		TotalTokens:  m.TotalTokens.Load(),
	}
}

// Ramp increases traffic to the experiment by one step. Returns true if a
// step was taken, false if there are no more steps or the experiment is not running.
func (ce *CanaryExperiment) Ramp() bool {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	if ce.status != CanaryStatusRunning {
		return false
	}

	if len(ce.config.RampSteps) == 0 {
		return false
	}

	nextIdx := ce.rampIdx + 1
	if nextIdx >= len(ce.config.RampSteps) {
		return false
	}

	ce.rampIdx = nextIdx
	ce.currentPct = ce.config.RampSteps[nextIdx]
	return true
}

// Rollback sets traffic to 0% experiment and marks the experiment as rolled back.
func (ce *CanaryExperiment) Rollback() {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	ce.status = CanaryStatusRolledBack
	ce.currentPct = 0
}

// Promote sets traffic to 100% experiment and marks the experiment as promoted.
func (ce *CanaryExperiment) Promote() {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	ce.status = CanaryStatusPromoted
	ce.currentPct = 100
}
