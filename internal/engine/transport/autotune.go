// autotune.go implements self-tuning connection pools that adjust their size
// based on observed latency.
//
// The tuner collects latency samples and compares the median against a target.
// If the median exceeds the target, the pool size is increased (up to a
// configured maximum) to provide more connections. If the median is well below
// the target, the pool size is decreased (down to a configured minimum) to
// release idle resources.
//
// Adjustments are made at most once per AdjustInterval to prevent oscillation.
// The suggested size is a recommendation; callers are responsible for applying
// it to their actual transport or pool configuration.
package transport

import (
	"sort"
	"sync"
	"time"
)

const (
	defaultMinConnections = 10
	defaultMaxConnections = 200
	defaultTargetLatency  = 100 // ms
	defaultAdjustInterval = 30 * time.Second
	maxSamples            = 1000

	// growFactor and shrinkThreshold control how aggressively the tuner adjusts.
	growFactor      = 1.25
	shrinkFactor    = 0.9
	shrinkThreshold = 0.5 // shrink if median < target * shrinkThreshold
)

// AutoTuneConfig configures self-tuning connection pools.
type AutoTuneConfig struct {
	MinConnections  int           `json:"min_connections" yaml:"min_connections"`
	MaxConnections  int           `json:"max_connections" yaml:"max_connections"`
	TargetLatencyMs int           `json:"target_latency_ms" yaml:"target_latency_ms"`
	AdjustInterval  time.Duration `json:"adjust_interval" yaml:"adjust_interval"`
}

// AutoTuner adjusts pool sizes based on latency feedback.
type AutoTuner struct {
	mu             sync.Mutex
	config         AutoTuneConfig
	currentSize    int
	latencySamples []float64
	lastAdjust     time.Time
}

// NewAutoTuner creates a new self-tuning pool sizer. Zero-value fields in cfg
// are replaced with sensible defaults.
func NewAutoTuner(cfg AutoTuneConfig) *AutoTuner {
	if cfg.MinConnections <= 0 {
		cfg.MinConnections = defaultMinConnections
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = defaultMaxConnections
	}
	if cfg.MaxConnections < cfg.MinConnections {
		cfg.MaxConnections = cfg.MinConnections
	}
	if cfg.TargetLatencyMs <= 0 {
		cfg.TargetLatencyMs = defaultTargetLatency
	}
	if cfg.AdjustInterval <= 0 {
		cfg.AdjustInterval = defaultAdjustInterval
	}

	return &AutoTuner{
		config:         cfg,
		currentSize:    cfg.MinConnections,
		latencySamples: make([]float64, 0, maxSamples),
		lastAdjust:     time.Now(),
	}
}

// RecordLatency adds a latency sample in milliseconds.
func (at *AutoTuner) RecordLatency(latencyMs float64) {
	at.mu.Lock()
	defer at.mu.Unlock()

	at.latencySamples = append(at.latencySamples, latencyMs)

	// Evict oldest samples if we exceed the buffer
	if len(at.latencySamples) > maxSamples {
		at.latencySamples = at.latencySamples[len(at.latencySamples)-maxSamples:]
	}
}

// SuggestedSize returns the recommended pool size based on recent latency.
// The size is adjusted at most once per AdjustInterval.
func (at *AutoTuner) SuggestedSize() int {
	at.mu.Lock()
	defer at.mu.Unlock()

	if len(at.latencySamples) == 0 {
		return at.currentSize
	}

	if time.Since(at.lastAdjust) < at.config.AdjustInterval {
		return at.currentSize
	}

	median := at.medianLocked()
	target := float64(at.config.TargetLatencyMs)

	newSize := at.currentSize
	if median > target {
		// Latency too high: grow the pool
		newSize = int(float64(at.currentSize) * growFactor)
		if newSize == at.currentSize {
			newSize++ // Ensure at least +1 growth
		}
	} else if median < target*shrinkThreshold {
		// Latency well under target: shrink the pool
		newSize = int(float64(at.currentSize) * shrinkFactor)
	}

	// Clamp to bounds
	if newSize < at.config.MinConnections {
		newSize = at.config.MinConnections
	}
	if newSize > at.config.MaxConnections {
		newSize = at.config.MaxConnections
	}

	at.currentSize = newSize
	at.lastAdjust = time.Now()
	at.latencySamples = at.latencySamples[:0] // Reset samples after adjustment

	return at.currentSize
}

// CurrentSize returns the current pool size.
func (at *AutoTuner) CurrentSize() int {
	at.mu.Lock()
	defer at.mu.Unlock()
	return at.currentSize
}

// medianLocked computes the median of the latency samples.
// Must be called with at.mu held.
func (at *AutoTuner) medianLocked() float64 {
	n := len(at.latencySamples)
	if n == 0 {
		return 0
	}

	// Sort a copy to avoid mutating the sample order
	sorted := make([]float64, n)
	copy(sorted, at.latencySamples)
	sort.Float64s(sorted)

	if n%2 == 0 {
		return (sorted[n/2-1] + sorted[n/2]) / 2
	}
	return sorted[n/2]
}
