// p2c_ewma.go implements Power-of-Two-Choices routing with PeakEWMA latency scoring.
//
// P2C picks two random providers from the candidate list and selects the one
// with the lower PeakEWMA score. PeakEWMA accounts for both the exponentially
// weighted moving average latency and the number of in-flight requests,
// so providers under heavy load or experiencing high latency are naturally
// deprioritized.
//
// EWMA formula: ewma = ewma * exp(-elapsed/decay) + latency * (1 - exp(-elapsed/decay))
// PeakEWMA score: ewma * (pending + 1)
package routing

import (
	"math"
	"math/rand"
	"sync"
	"time"
)

const defaultDecayNs = int64(10 * time.Second)

// P2CEWMAConfig configures Power-of-Two-Choices with PeakEWMA routing.
type P2CEWMAConfig struct {
	DecayNs int64 `json:"ewma_decay_ns,omitempty" yaml:"ewma_decay_ns"` // default 10s
}

// P2CEWMARouter implements P2C with exponentially weighted moving average latency.
type P2CEWMARouter struct {
	mu      sync.RWMutex
	metrics map[string]*ewmaMetric // provider name -> metric
	decayNs float64
}

type ewmaMetric struct {
	ewma     float64 // EWMA latency in nanoseconds
	lastTime time.Time
	pending  int64 // in-flight requests
}

// NewP2CEWMARouter creates a new P2C + PeakEWMA router.
func NewP2CEWMARouter(cfg P2CEWMAConfig) *P2CEWMARouter {
	decay := float64(cfg.DecayNs)
	if decay <= 0 {
		decay = float64(defaultDecayNs)
	}
	return &P2CEWMARouter{
		metrics: make(map[string]*ewmaMetric),
		decayNs: decay,
	}
}

// Select picks the best provider from the list using P2C + PeakEWMA.
// If there are fewer than two providers, the first (or only) provider is returned.
// An empty list returns an empty string.
func (r *P2CEWMARouter) Select(providers []string) string {
	n := len(providers)
	if n == 0 {
		return ""
	}
	if n == 1 {
		return providers[0]
	}

	// Pick two distinct random indices
	i := rand.Intn(n)
	j := rand.Intn(n - 1)
	if j >= i {
		j++
	}

	r.mu.RLock()
	scoreA := r.score(providers[i])
	scoreB := r.score(providers[j])
	r.mu.RUnlock()

	if scoreA <= scoreB {
		return providers[i]
	}
	return providers[j]
}

// score computes the PeakEWMA score for a provider. Must be called with r.mu held.
func (r *P2CEWMARouter) score(provider string) float64 {
	m, ok := r.metrics[provider]
	if !ok {
		// Unknown providers get zero score so they are tried first.
		return 0
	}

	// Decay the EWMA to the current time
	elapsed := float64(time.Since(m.lastTime).Nanoseconds())
	decayFactor := math.Exp(-elapsed / r.decayNs)
	decayedEWMA := m.ewma * decayFactor

	// PeakEWMA: factor in queue depth
	return decayedEWMA * float64(m.pending+1)
}

// RecordLatency updates the EWMA metric for a provider after a request completes.
func (r *P2CEWMARouter) RecordLatency(provider string, latency time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	m := r.getOrCreate(provider)
	now := time.Now()

	elapsed := float64(now.Sub(m.lastTime).Nanoseconds())
	w := math.Exp(-elapsed / r.decayNs)
	latencyNs := float64(latency.Nanoseconds())

	m.ewma = m.ewma*w + latencyNs*(1-w)
	m.lastTime = now
}

// IncrementPending marks a provider as having an additional in-flight request.
func (r *P2CEWMARouter) IncrementPending(provider string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.getOrCreate(provider).pending++
}

// DecrementPending marks a provider as having one fewer in-flight request.
func (r *P2CEWMARouter) DecrementPending(provider string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.getOrCreate(provider)
	if m.pending > 0 {
		m.pending--
	}
}

// getOrCreate returns the metric for a provider, creating it if needed.
// Must be called with r.mu held for writing.
func (r *P2CEWMARouter) getOrCreate(provider string) *ewmaMetric {
	m, ok := r.metrics[provider]
	if !ok {
		m = &ewmaMetric{lastTime: time.Now()}
		r.metrics[provider] = m
	}
	return m
}
