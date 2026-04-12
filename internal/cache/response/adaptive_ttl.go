// Package handler contains the core HTTP request handler that orchestrates the proxy pipeline.
package responsecache

import (
	"log/slog"
	"math"
	"sort"
	"sync"
	"time"
)

// AdaptiveTTLConfig configures adaptive TTL adjustment.
type AdaptiveTTLConfig struct {
	Enabled        bool          `json:"enabled,omitempty"`
	MinTTL         time.Duration `json:"min_ttl,omitempty"`         // Floor TTL (default: 10s)
	MaxTTL         time.Duration `json:"max_ttl,omitempty"`         // Ceiling TTL (default: 24h)
	SampleWindow   int           `json:"sample_window,omitempty"`   // Number of change intervals to track (default: 10)
	StabilityBonus float64       `json:"stability_bonus,omitempty"` // Multiplier for stable content (default: 1.5)
}

// AdaptiveTTLStats holds per-key statistics for adaptive TTL.
type AdaptiveTTLStats struct {
	Key            string        `json:"key"`
	CurrentTTL     time.Duration `json:"current_ttl"`
	SampleCount    int           `json:"sample_count"`
	MedianInterval time.Duration `json:"median_interval"`
	LastModified   time.Time     `json:"last_modified"`
	LastChecked    time.Time     `json:"last_checked"`
}

// AdaptiveTTL tracks content change frequency and computes optimal TTL.
type AdaptiveTTL struct {
	config  AdaptiveTTLConfig
	mu      sync.RWMutex
	entries map[string]*ttlEntry // keyed by cache key
}

type ttlEntry struct {
	intervals    []time.Duration // Recent change intervals
	lastModified time.Time
	lastChecked  time.Time
	currentTTL   time.Duration
}

// NewAdaptiveTTL creates a new AdaptiveTTL tracker with the given config.
func NewAdaptiveTTL(config AdaptiveTTLConfig) *AdaptiveTTL {
	if config.MinTTL <= 0 {
		config.MinTTL = 10 * time.Second
	}
	if config.MaxTTL <= 0 {
		config.MaxTTL = 24 * time.Hour
	}
	if config.SampleWindow <= 0 {
		config.SampleWindow = 10
	}
	if config.StabilityBonus <= 0 {
		config.StabilityBonus = 1.5
	}
	// Ensure min <= max
	if config.MinTTL > config.MaxTTL {
		config.MinTTL = config.MaxTTL
	}

	return &AdaptiveTTL{
		config:  config,
		entries: make(map[string]*ttlEntry),
	}
}

// RecordChange records a content change for the given key, updating the change interval history.
func (a *AdaptiveTTL) RecordChange(key string, lastModified time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	entry, ok := a.entries[key]
	if !ok {
		entry = &ttlEntry{
			lastModified: lastModified,
			lastChecked:  time.Now(),
		}
		a.entries[key] = entry
		slog.Debug("adaptive_ttl: new key tracked", "key", key)
		return
	}

	// Compute interval since last modification
	if !entry.lastModified.IsZero() && lastModified.After(entry.lastModified) {
		interval := lastModified.Sub(entry.lastModified)
		entry.intervals = append(entry.intervals, interval)

		// Trim to sample window
		if len(entry.intervals) > a.config.SampleWindow {
			entry.intervals = entry.intervals[len(entry.intervals)-a.config.SampleWindow:]
		}

		// Recompute TTL
		entry.currentTTL = a.computeTTL(entry)
		slog.Debug("adaptive_ttl: recorded change",
			"key", key,
			"interval", interval,
			"new_ttl", entry.currentTTL,
			"samples", len(entry.intervals))
	}

	entry.lastModified = lastModified
	entry.lastChecked = time.Now()
}

// GetTTL returns the adaptive TTL for the given key. If no change data exists, defaultTTL is used.
func (a *AdaptiveTTL) GetTTL(key string, defaultTTL time.Duration) time.Duration {
	a.mu.RLock()
	defer a.mu.RUnlock()

	entry, ok := a.entries[key]
	if !ok || len(entry.intervals) == 0 {
		// No data - content appears stable, apply stability bonus
		ttl := time.Duration(float64(defaultTTL) * a.config.StabilityBonus)
		return a.clamp(ttl)
	}

	if entry.currentTTL > 0 {
		return entry.currentTTL
	}

	return a.clamp(a.computeTTL(entry))
}

// Stats returns per-key statistics for all tracked keys.
func (a *AdaptiveTTL) Stats() map[string]AdaptiveTTLStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	stats := make(map[string]AdaptiveTTLStats, len(a.entries))
	for key, entry := range a.entries {
		s := AdaptiveTTLStats{
			Key:          key,
			CurrentTTL:   entry.currentTTL,
			SampleCount:  len(entry.intervals),
			LastModified: entry.lastModified,
			LastChecked:  entry.lastChecked,
		}
		if len(entry.intervals) > 0 {
			s.MedianInterval = medianDuration(entry.intervals)
		}
		stats[key] = s
	}
	return stats
}

// computeTTL calculates the TTL from the entry's change intervals.
// For frequent changes: median_interval / 2 (aggressive caching).
// For stable content: median_interval * stability_bonus.
func (a *AdaptiveTTL) computeTTL(entry *ttlEntry) time.Duration {
	if len(entry.intervals) == 0 {
		return a.config.MinTTL
	}

	median := medianDuration(entry.intervals)

	// Compute coefficient of variation to measure stability.
	// Low CV = stable content, high CV = erratic changes.
	mean := averageDuration(entry.intervals)
	variance := float64(0)
	for _, d := range entry.intervals {
		diff := float64(d) - float64(mean)
		variance += diff * diff
	}
	variance /= float64(len(entry.intervals))
	stddev := time.Duration(math.Sqrt(variance))

	var ttl time.Duration
	if mean > 0 {
		cv := float64(stddev) / float64(mean)
		if cv < 0.5 {
			// Stable content - use stability bonus
			ttl = time.Duration(float64(median) * a.config.StabilityBonus)
		} else {
			// Erratic or frequent changes - be more conservative
			ttl = median / 2
		}
	} else {
		ttl = median / 2
	}

	return a.clamp(ttl)
}

// clamp restricts a TTL to the configured [MinTTL, MaxTTL] bounds.
func (a *AdaptiveTTL) clamp(ttl time.Duration) time.Duration {
	if ttl < a.config.MinTTL {
		return a.config.MinTTL
	}
	if ttl > a.config.MaxTTL {
		return a.config.MaxTTL
	}
	return ttl
}

// medianDuration returns the median value from a slice of durations.
func medianDuration(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(durations))
	copy(sorted, durations)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[mid-1] + sorted[mid]) / 2
	}
	return sorted[mid]
}

// averageDuration returns the arithmetic mean of a slice of durations.
func averageDuration(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	var sum time.Duration
	for _, d := range durations {
		sum += d
	}
	return sum / time.Duration(len(durations))
}
