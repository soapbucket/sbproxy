// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"crypto/rand"
	"encoding/binary"
	"hash/fnv"
	mathrand "math/rand/v2"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ABTestConfig configures an A/B test experiment.
type ABTestConfig struct {
	Enabled   bool        `json:"enabled"`
	Name      string      `json:"name"`
	Variants  []ABVariant `json:"variants"`
	StickyKey string      `json:"sticky_key,omitempty"` // Header for sticky assignment (e.g., "X-User-ID")
}

// ABVariant defines a single variant in an A/B test.
type ABVariant struct {
	Name        string   `json:"name"`
	Weight      float64  `json:"weight"`
	Provider    string   `json:"provider,omitempty"`
	Model       string   `json:"model,omitempty"`
	Temperature *float64 `json:"temperature,omitempty"`
	MaxTokens   int      `json:"max_tokens,omitempty"`
}

// ABTestRouter selects a variant for each request and tracks per-variant metrics.
type ABTestRouter struct {
	config   ABTestConfig
	metrics  map[string]*VariantMetrics
	mu       sync.RWMutex
	sticky   map[string]string
	stickyMu sync.RWMutex
	rng      *mathrand.Rand
	rngMu    sync.Mutex
}

// VariantMetrics tracks performance metrics for a single A/B test variant.
type VariantMetrics struct {
	Requests     atomic.Int64
	Tokens       atomic.Int64
	Errors       atomic.Int64
	TotalLatency atomic.Int64 // Microseconds
	P50Latency   atomic.Int64 // Approximate
	P99Latency   atomic.Int64 // Approximate
}

// NewABTestRouter creates a new ABTestRouter with the given configuration.
func NewABTestRouter(config ABTestConfig) *ABTestRouter {
	var seed [8]byte
	_, _ = rand.Read(seed[:])
	src := mathrand.NewPCG(binary.LittleEndian.Uint64(seed[:]), 0)

	metrics := make(map[string]*VariantMetrics, len(config.Variants))
	for _, v := range config.Variants {
		metrics[v.Name] = &VariantMetrics{}
	}

	return &ABTestRouter{
		config:  config,
		metrics: metrics,
		sticky:  make(map[string]string),
		rng:     mathrand.New(src),
	}
}

// SelectVariant picks a variant for the request.
// If StickyKey is configured and the header is present, the same variant is returned
// for the same key value across requests.
func (ab *ABTestRouter) SelectVariant(r *http.Request) *ABVariant {
	if len(ab.config.Variants) == 0 {
		return nil
	}

	// Check sticky assignment
	if ab.config.StickyKey != "" && r != nil {
		key := r.Header.Get(ab.config.StickyKey)
		if key != "" {
			// Check existing assignment
			ab.stickyMu.RLock()
			name, ok := ab.sticky[key]
			ab.stickyMu.RUnlock()
			if ok {
				return ab.findVariant(name)
			}

			// Deterministic assignment based on key hash
			variant := ab.hashSelect(key)
			ab.stickyMu.Lock()
			ab.sticky[key] = variant.Name
			ab.stickyMu.Unlock()
			return variant
		}
	}

	// Random weighted selection
	return ab.weightedSelect()
}

// RecordResult records metrics for a variant after a request completes.
func (ab *ABTestRouter) RecordResult(variantName string, tokens int, latency time.Duration, err error) {
	ab.mu.RLock()
	m, ok := ab.metrics[variantName]
	ab.mu.RUnlock()
	if !ok {
		return
	}

	m.Requests.Add(1)
	m.Tokens.Add(int64(tokens))
	latUS := latency.Microseconds()
	m.TotalLatency.Add(latUS)

	if err != nil {
		m.Errors.Add(1)
	}

	// Approximate percentile tracking using exponential moving average.
	// This is a rough approximation, not a true percentile.
	updateApproxPercentile(&m.P50Latency, latUS, 0.05)
	updateApproxPercentile(&m.P99Latency, latUS, 0.01)
}

// GetMetrics returns metrics for all variants.
func (ab *ABTestRouter) GetMetrics() map[string]*VariantMetrics {
	ab.mu.RLock()
	defer ab.mu.RUnlock()
	// Return the map directly. Callers read atomics.
	result := make(map[string]*VariantMetrics, len(ab.metrics))
	for k, v := range ab.metrics {
		result[k] = v
	}
	return result
}

// Reset clears all metrics and sticky assignments.
func (ab *ABTestRouter) Reset() {
	ab.mu.Lock()
	for _, m := range ab.metrics {
		m.Requests.Store(0)
		m.Tokens.Store(0)
		m.Errors.Store(0)
		m.TotalLatency.Store(0)
		m.P50Latency.Store(0)
		m.P99Latency.Store(0)
	}
	ab.mu.Unlock()

	ab.stickyMu.Lock()
	ab.sticky = make(map[string]string)
	ab.stickyMu.Unlock()
}

// findVariant returns the variant with the given name, or nil.
func (ab *ABTestRouter) findVariant(name string) *ABVariant {
	for i := range ab.config.Variants {
		if ab.config.Variants[i].Name == name {
			return &ab.config.Variants[i]
		}
	}
	return nil
}

// weightedSelect picks a variant based on configured weights using the local RNG.
func (ab *ABTestRouter) weightedSelect() *ABVariant {
	totalWeight := 0.0
	for _, v := range ab.config.Variants {
		totalWeight += v.Weight
	}
	if totalWeight <= 0 {
		return &ab.config.Variants[0]
	}

	ab.rngMu.Lock()
	target := ab.rng.Float64() * totalWeight
	ab.rngMu.Unlock()

	cumulative := 0.0
	for i := range ab.config.Variants {
		cumulative += ab.config.Variants[i].Weight
		if target < cumulative {
			return &ab.config.Variants[i]
		}
	}
	return &ab.config.Variants[len(ab.config.Variants)-1]
}

// hashSelect deterministically picks a variant based on a string key.
func (ab *ABTestRouter) hashSelect(key string) *ABVariant {
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	hashVal := h.Sum64()

	totalWeight := 0.0
	for _, v := range ab.config.Variants {
		totalWeight += v.Weight
	}
	if totalWeight <= 0 {
		return &ab.config.Variants[0]
	}

	// Map hash to [0, totalWeight)
	target := float64(hashVal%10000) / 10000.0 * totalWeight

	cumulative := 0.0
	for i := range ab.config.Variants {
		cumulative += ab.config.Variants[i].Weight
		if target < cumulative {
			return &ab.config.Variants[i]
		}
	}
	return &ab.config.Variants[len(ab.config.Variants)-1]
}

// updateApproxPercentile updates an approximate percentile using exponential moving average.
func updateApproxPercentile(target *atomic.Int64, sample int64, alpha float64) {
	for {
		old := target.Load()
		if old == 0 {
			if target.CompareAndSwap(0, sample) {
				return
			}
			continue
		}
		// EMA: new = old + alpha * (sample - old)
		diff := float64(sample - old)
		newVal := old + int64(alpha*diff)
		if target.CompareAndSwap(old, newVal) {
			return
		}
	}
}
