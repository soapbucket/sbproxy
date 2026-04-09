// Package handler contains the core HTTP request handler that orchestrates the proxy pipeline.
package responsecache

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	cacheTierHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_cache_tier_hits_total",
		Help: "Cache hits by tier and origin",
	}, []string{"tier", "origin"})

	cacheTierMisses = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_cache_tier_misses_total",
		Help: "Cache misses by tier and origin",
	}, []string{"tier", "origin"})

	cacheTierSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_cache_tier_size_bytes",
		Help: "Current cache size by tier",
	}, []string{"tier"})

	cacheTierEvictions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_cache_tier_evictions_total",
		Help: "Cache evictions by tier and reason",
	}, []string{"tier", "reason"})

	cacheTierLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_cache_tier_latency_seconds",
		Help:    "Cache operation latency by tier and operation",
		Buckets: prometheus.DefBuckets,
	}, []string{"tier", "operation"})
)

// TierStatsSnapshot holds a point-in-time snapshot of a cache tier's statistics.
type TierStatsSnapshot struct {
	Hits      int64   `json:"hits"`
	Misses    int64   `json:"misses"`
	HitRate   float64 `json:"hit_rate"`
	Evictions int64   `json:"evictions"`
	SizeBytes int64   `json:"size_bytes"`
	ItemCount int64   `json:"item_count"`
}

// CacheTierAnalytics tracks per-tier cache metrics.
type CacheTierAnalytics struct {
	tiers map[string]*tierStats
	mu    sync.RWMutex
}

type tierStats struct {
	hits      atomic.Int64
	misses    atomic.Int64
	evictions atomic.Int64
	sizeBytes atomic.Int64
	itemCount atomic.Int64
}

// NewCacheTierAnalytics creates a new CacheTierAnalytics tracker.
func NewCacheTierAnalytics() *CacheTierAnalytics {
	return &CacheTierAnalytics{
		tiers: make(map[string]*tierStats),
	}
}

// getOrCreate returns the tierStats for the given tier, creating it if necessary.
func (c *CacheTierAnalytics) getOrCreate(tier string) *tierStats {
	c.mu.RLock()
	ts, ok := c.tiers[tier]
	c.mu.RUnlock()
	if ok {
		return ts
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// Double-check after write lock
	if ts, ok = c.tiers[tier]; ok {
		return ts
	}
	ts = &tierStats{}
	c.tiers[tier] = ts
	return ts
}

// RecordHit records a cache hit for the given tier and origin.
func (c *CacheTierAnalytics) RecordHit(tier, origin string) {
	ts := c.getOrCreate(tier)
	ts.hits.Add(1)
	cacheTierHits.WithLabelValues(tier, origin).Inc()
}

// RecordMiss records a cache miss for the given tier and origin.
func (c *CacheTierAnalytics) RecordMiss(tier, origin string) {
	ts := c.getOrCreate(tier)
	ts.misses.Add(1)
	cacheTierMisses.WithLabelValues(tier, origin).Inc()
}

// RecordEviction records a cache eviction for the given tier and reason.
func (c *CacheTierAnalytics) RecordEviction(tier, reason string) {
	ts := c.getOrCreate(tier)
	ts.evictions.Add(1)
	cacheTierEvictions.WithLabelValues(tier, reason).Inc()
}

// UpdateSize updates the current size in bytes for the given tier.
func (c *CacheTierAnalytics) UpdateSize(tier string, sizeBytes int64) {
	ts := c.getOrCreate(tier)
	ts.sizeBytes.Store(sizeBytes)
	cacheTierSize.WithLabelValues(tier).Set(float64(sizeBytes))
}

// UpdateItemCount updates the item count for the given tier.
func (c *CacheTierAnalytics) UpdateItemCount(tier string, count int64) {
	ts := c.getOrCreate(tier)
	ts.itemCount.Store(count)
}

// RecordLatency records the latency for a cache operation on the given tier.
func (c *CacheTierAnalytics) RecordLatency(tier, operation string, duration time.Duration) {
	cacheTierLatency.WithLabelValues(tier, operation).Observe(duration.Seconds())
}

// HitRate returns the hit rate as a percentage (0-100) for the given tier.
// Returns 0 if no requests have been recorded.
func (c *CacheTierAnalytics) HitRate(tier string) float64 {
	c.mu.RLock()
	ts, ok := c.tiers[tier]
	c.mu.RUnlock()
	if !ok {
		return 0
	}

	hits := ts.hits.Load()
	misses := ts.misses.Load()
	total := hits + misses
	if total == 0 {
		return 0
	}
	return float64(hits) / float64(total) * 100
}

// Stats returns a snapshot of all tier statistics.
func (c *CacheTierAnalytics) Stats() map[string]TierStatsSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]TierStatsSnapshot, len(c.tiers))
	for name, ts := range c.tiers {
		hits := ts.hits.Load()
		misses := ts.misses.Load()
		total := hits + misses
		var hitRate float64
		if total > 0 {
			hitRate = float64(hits) / float64(total) * 100
		}
		result[name] = TierStatsSnapshot{
			Hits:      hits,
			Misses:    misses,
			HitRate:   hitRate,
			Evictions: ts.evictions.Load(),
			SizeBytes: ts.sizeBytes.Load(),
			ItemCount: ts.itemCount.Load(),
		}
	}
	return result
}
