// Package transform applies content transformations to HTTP request and response bodies.
package transformer

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	transformDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_transform_duration_seconds",
		Help:    "Per-transform execution duration",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0},
	}, []string{"transform_name", "origin"})

	transformErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_transform_errors_total",
		Help: "Transform error count by name",
	}, []string{"transform_name", "origin"})

	transformBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_transform_bytes_processed_total",
		Help: "Bytes processed by each transform",
	}, []string{"transform_name", "origin", "direction"})
)

// CostTracker accumulates transform execution costs.
type CostTracker struct {
	mu      sync.RWMutex
	entries map[string]*transformCost
}

type transformCost struct {
	name          string
	totalDuration atomic.Int64 // nanoseconds
	executions    atomic.Int64
	errors        atomic.Int64
	bytesIn       atomic.Int64
	bytesOut      atomic.Int64
}

// TransformCostSnapshot is a point-in-time view of a transform's cost.
type TransformCostSnapshot struct {
	Name          string        `json:"name"`
	TotalDuration time.Duration `json:"total_duration"`
	Executions    int64         `json:"executions"`
	AvgDuration   time.Duration `json:"avg_duration"`
	Errors        int64         `json:"errors"`
	BytesIn       int64         `json:"bytes_in"`
	BytesOut      int64         `json:"bytes_out"`
}

// NewCostTracker creates a new CostTracker.
func NewCostTracker() *CostTracker {
	return &CostTracker{
		entries: make(map[string]*transformCost),
	}
}

// Record records a transform execution and emits Prometheus metrics.
func (ct *CostTracker) Record(name, origin string, duration time.Duration, bytesIn, bytesOut int64, err error) {
	// Emit Prometheus metrics.
	transformDuration.WithLabelValues(name, origin).Observe(duration.Seconds())
	transformBytes.WithLabelValues(name, origin, "in").Add(float64(bytesIn))
	transformBytes.WithLabelValues(name, origin, "out").Add(float64(bytesOut))
	if err != nil {
		transformErrors.WithLabelValues(name, origin).Inc()
	}

	// Update internal tracking.
	ct.mu.RLock()
	entry, ok := ct.entries[name]
	ct.mu.RUnlock()

	if !ok {
		ct.mu.Lock()
		// Double-check after acquiring write lock.
		entry, ok = ct.entries[name]
		if !ok {
			entry = &transformCost{name: name}
			ct.entries[name] = entry
		}
		ct.mu.Unlock()
	}

	entry.totalDuration.Add(int64(duration))
	entry.executions.Add(1)
	entry.bytesIn.Add(bytesIn)
	entry.bytesOut.Add(bytesOut)
	if err != nil {
		entry.errors.Add(1)
	}
}

// Snapshot returns all transform costs sorted by total duration descending.
func (ct *CostTracker) Snapshot() []TransformCostSnapshot {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	snapshots := make([]TransformCostSnapshot, 0, len(ct.entries))
	for _, entry := range ct.entries {
		totalDur := time.Duration(entry.totalDuration.Load())
		execs := entry.executions.Load()
		var avgDur time.Duration
		if execs > 0 {
			avgDur = totalDur / time.Duration(execs)
		}

		snapshots = append(snapshots, TransformCostSnapshot{
			Name:          entry.name,
			TotalDuration: totalDur,
			Executions:    execs,
			AvgDuration:   avgDur,
			Errors:        entry.errors.Load(),
			BytesIn:       entry.bytesIn.Load(),
			BytesOut:      entry.bytesOut.Load(),
		})
	}

	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].TotalDuration > snapshots[j].TotalDuration
	})

	return snapshots
}

// Reset clears all tracked entries.
func (ct *CostTracker) Reset() {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.entries = make(map[string]*transformCost)
}
