package policy

import (
	"hash/fnv"
	"sync"
	"time"
)

// TPMLimiter tracks tokens-per-minute with a sliding window.
// It uses 16 shards for concurrent access.
type TPMLimiter struct {
	shards [16]tpmShard
}

type tpmShard struct {
	mu      sync.Mutex
	windows map[string]*slidingWindow
}

type slidingWindow struct {
	buckets    [60]int64 // One per second in the minute
	currentIdx int
	lastUpdate time.Time
	total      int64
}

// NewTPMLimiter creates a new TPM limiter.
func NewTPMLimiter() *TPMLimiter {
	t := &TPMLimiter{}
	for i := range t.shards {
		t.shards[i].windows = make(map[string]*slidingWindow)
	}
	return t
}

// shardFor returns the shard index for a given key.
func (t *TPMLimiter) shardFor(key string) *tpmShard {
	h := fnv.New32a()
	h.Write([]byte(key))
	return &t.shards[h.Sum32()%16]
}

// Check returns true if adding tokens would stay within the limit.
func (t *TPMLimiter) Check(key string, tokens int64, limit int64) bool {
	shard := t.shardFor(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	w, ok := shard.windows[key]
	if !ok {
		return tokens <= limit
	}

	t.advanceWindow(w)
	return (w.total + tokens) <= limit
}

// Record adds token usage for the current second.
func (t *TPMLimiter) Record(key string, tokens int64) {
	shard := t.shardFor(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	w, ok := shard.windows[key]
	if !ok {
		w = &slidingWindow{
			lastUpdate: time.Now(),
		}
		shard.windows[key] = w
	}

	t.advanceWindow(w)
	w.buckets[w.currentIdx] += tokens
	w.total += tokens
}

// Usage returns current TPM for a key.
func (t *TPMLimiter) Usage(key string) int64 {
	shard := t.shardFor(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	w, ok := shard.windows[key]
	if !ok {
		return 0
	}

	t.advanceWindow(w)
	return w.total
}

// advanceWindow moves the window forward to the current time, clearing expired buckets.
// Must be called with the shard lock held.
func (t *TPMLimiter) advanceWindow(w *slidingWindow) {
	now := time.Now()
	elapsed := now.Sub(w.lastUpdate)

	if elapsed < time.Second {
		return
	}

	seconds := int(elapsed / time.Second)
	if seconds > 60 {
		seconds = 60
	}

	// Clear buckets that have expired.
	for i := 0; i < seconds; i++ {
		nextIdx := (w.currentIdx + 1 + i) % 60
		w.total -= w.buckets[nextIdx]
		if w.total < 0 {
			w.total = 0
		}
		w.buckets[nextIdx] = 0
	}

	w.currentIdx = (w.currentIdx + seconds) % 60
	w.lastUpdate = now
}
