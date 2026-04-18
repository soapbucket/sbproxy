// fill_first.go implements fill-first routing that exhausts one provider
// before moving to the next.
//
// This strategy is useful when one provider is cheaper or preferred for
// contractual reasons and should receive all traffic until its capacity
// is exhausted. Once a provider reaches its configured request limit,
// subsequent calls spill over to the next provider in the ordered list.
package routing

import (
	"sync"
	"sync/atomic"
)

// FillFirstConfig configures fill-first routing.
type FillFirstConfig struct {
	MaxRequestsPerProvider int `json:"max_requests_per_provider,omitempty" yaml:"max_requests_per_provider"`
}

// FillFirstRouter sends all traffic to the first provider until it hits limits,
// then overflows to the next provider in the ordered list.
type FillFirstRouter struct {
	mu        sync.RWMutex
	providers []string
	counts    map[string]*atomic.Int64
	maxReqs   int
}

// NewFillFirstRouter creates a new fill-first router with the given provider order.
// If cfg.MaxRequestsPerProvider is zero or negative, no limit is applied (all
// traffic goes to the first provider forever).
func NewFillFirstRouter(providers []string, cfg FillFirstConfig) *FillFirstRouter {
	counts := make(map[string]*atomic.Int64, len(providers))
	for _, p := range providers {
		counts[p] = &atomic.Int64{}
	}
	return &FillFirstRouter{
		providers: providers,
		counts:    counts,
		maxReqs:   cfg.MaxRequestsPerProvider,
	}
}

// Select returns the first non-exhausted provider. If all providers are
// exhausted, ok is false.
func (r *FillFirstRouter) Select() (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, p := range r.providers {
		if r.maxReqs <= 0 {
			// No limit configured; always use the first provider.
			return p, true
		}
		counter, ok := r.counts[p]
		if !ok {
			continue
		}
		if counter.Load() < int64(r.maxReqs) {
			return p, true
		}
	}
	return "", false
}

// RecordRequest increments the request count for a provider.
func (r *FillFirstRouter) RecordRequest(provider string) {
	r.mu.RLock()
	counter, ok := r.counts[provider]
	r.mu.RUnlock()
	if ok {
		counter.Add(1)
	}
}

// Reset clears all request counts (e.g., on time window reset).
func (r *FillFirstRouter) Reset() {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, counter := range r.counts {
		counter.Store(0)
	}
}
