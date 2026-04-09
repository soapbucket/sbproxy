// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"hash/fnv"
	"sync"
	"time"
)

// agentRateTracker tracks per-agent request and token rates using a sliding window.
type agentRateTracker struct {
	windows    [16]sync.Map
	windowSize time.Duration
}

type rateWindow struct {
	Requests []time.Time
	Tokens   []tokenEntry
	mu       sync.Mutex
}

type tokenEntry struct {
	Count     int64
	Timestamp time.Time
}

func newAgentRateTracker(windowSize time.Duration) *agentRateTracker {
	if windowSize <= 0 {
		windowSize = time.Minute
	}
	return &agentRateTracker{
		windowSize: windowSize,
	}
}

// shard returns the shard index for the given key using FNV-1a.
func (art *agentRateTracker) shard(key string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(key))
	return h.Sum32() % 16
}

// getWindow returns the rateWindow for the given key, creating one if it does not exist.
func (art *agentRateTracker) getWindow(key string) *rateWindow {
	shard := art.shard(key)
	val, ok := art.windows[shard].Load(key)
	if ok {
		return val.(*rateWindow)
	}
	w := &rateWindow{}
	actual, _ := art.windows[shard].LoadOrStore(key, w)
	return actual.(*rateWindow)
}

// RecordRequest records a request timestamp for the given key.
func (art *agentRateTracker) RecordRequest(key string) {
	w := art.getWindow(key)
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	w.Requests = art.pruneTimestamps(w.Requests, now)
	w.Requests = append(w.Requests, now)
}

// RecordTokens records a token usage entry for the given key.
func (art *agentRateTracker) RecordTokens(key string, tokens int64) {
	w := art.getWindow(key)
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	w.Tokens = art.pruneTokenEntries(w.Tokens, now)
	w.Tokens = append(w.Tokens, tokenEntry{Count: tokens, Timestamp: now})
}

// RequestsInWindow returns the number of requests within the current sliding window.
func (art *agentRateTracker) RequestsInWindow(key string) int {
	w := art.getWindow(key)
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	w.Requests = art.pruneTimestamps(w.Requests, now)
	return len(w.Requests)
}

// TokensInWindow returns the total tokens within the current sliding window.
func (art *agentRateTracker) TokensInWindow(key string) int64 {
	w := art.getWindow(key)
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	w.Tokens = art.pruneTokenEntries(w.Tokens, now)
	var total int64
	for _, entry := range w.Tokens {
		total += entry.Count
	}
	return total
}

// pruneTimestamps removes timestamps older than the window from the slice.
func (art *agentRateTracker) pruneTimestamps(timestamps []time.Time, now time.Time) []time.Time {
	cutoff := now.Add(-art.windowSize)
	// Find the first timestamp that is within the window.
	start := 0
	for start < len(timestamps) && timestamps[start].Before(cutoff) {
		start++
	}
	if start == 0 {
		return timestamps
	}
	// Compact in place to avoid allocation when possible.
	n := copy(timestamps, timestamps[start:])
	return timestamps[:n]
}

// pruneTokenEntries removes token entries older than the window from the slice.
func (art *agentRateTracker) pruneTokenEntries(entries []tokenEntry, now time.Time) []tokenEntry {
	cutoff := now.Add(-art.windowSize)
	start := 0
	for start < len(entries) && entries[start].Timestamp.Before(cutoff) {
		start++
	}
	if start == 0 {
		return entries
	}
	n := copy(entries, entries[start:])
	return entries[:n]
}
