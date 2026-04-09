package cache

import (
	"sync/atomic"
	"time"
)

// Analytics tracks cache performance statistics.
type Analytics struct {
	hits           int64
	misses         int64
	semanticHits   int64
	exactHits      int64
	latencySavedMs int64 // accumulated milliseconds saved
	costSavedUSD   int64 // accumulated cost saved in microdollars (1/1000000 USD)
	startTime      time.Time
}

// NewAnalytics creates a new cache analytics tracker.
func NewAnalytics() *Analytics {
	return &Analytics{startTime: time.Now()}
}

// RecordHit records a cache hit with estimated savings.
func (a *Analytics) RecordHit(cacheType string, estimatedLatencyMs int64, estimatedCostMicroUSD int64) {
	atomic.AddInt64(&a.hits, 1)
	atomic.AddInt64(&a.latencySavedMs, estimatedLatencyMs)
	atomic.AddInt64(&a.costSavedUSD, estimatedCostMicroUSD)
	switch cacheType {
	case "semantic":
		atomic.AddInt64(&a.semanticHits, 1)
	case "exact":
		atomic.AddInt64(&a.exactHits, 1)
	}
}

// RecordMiss records a cache miss.
func (a *Analytics) RecordMiss() {
	atomic.AddInt64(&a.misses, 1)
}

// Stats returns a snapshot of current cache analytics.
func (a *Analytics) Stats() CacheStats {
	hits := atomic.LoadInt64(&a.hits)
	misses := atomic.LoadInt64(&a.misses)
	total := hits + misses
	var hitRate float64
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}

	return CacheStats{
		Hits:              hits,
		Misses:            misses,
		SemanticHits:      atomic.LoadInt64(&a.semanticHits),
		ExactHits:         atomic.LoadInt64(&a.exactHits),
		HitRate:           hitRate,
		TotalRequests:     total,
		LatencySavedMs:    atomic.LoadInt64(&a.latencySavedMs),
		CostSavedMicroUSD: atomic.LoadInt64(&a.costSavedUSD),
		UptimeSeconds:     int64(time.Since(a.startTime).Seconds()),
	}
}

// CacheStats holds a point-in-time snapshot of cache performance.
type CacheStats struct {
	Hits              int64   `json:"hits"`
	Misses            int64   `json:"misses"`
	SemanticHits      int64   `json:"semantic_hits"`
	ExactHits         int64   `json:"exact_hits"`
	HitRate           float64 `json:"hit_rate"`
	TotalRequests     int64   `json:"total_requests"`
	LatencySavedMs    int64   `json:"latency_saved_ms"`
	CostSavedMicroUSD int64   `json:"cost_saved_micro_usd"`
	UptimeSeconds     int64   `json:"uptime_seconds"`
}
