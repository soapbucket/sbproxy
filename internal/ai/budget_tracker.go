// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"context"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// TokenUsage tracks token consumption for a specific scope+period.
type TokenUsage struct {
	InputTokens  atomic.Int64
	OutputTokens atomic.Int64
	TotalTokens  atomic.Int64
	PeriodStart  time.Time
	PeriodEnd    time.Time
}

// TokenUsageSnapshot is a non-atomic copy of TokenUsage for reading.
type TokenUsageSnapshot struct {
	InputTokens  int64     `json:"input_tokens"`
	OutputTokens int64     `json:"output_tokens"`
	TotalTokens  int64     `json:"total_tokens"`
	PeriodStart  time.Time `json:"period_start"`
	PeriodEnd    time.Time `json:"period_end"`
}

// Snapshot returns a point-in-time copy of the usage counters.
func (u *TokenUsage) Snapshot() TokenUsageSnapshot {
	return TokenUsageSnapshot{
		InputTokens:  u.InputTokens.Load(),
		OutputTokens: u.OutputTokens.Load(),
		TotalTokens:  u.TotalTokens.Load(),
		PeriodStart:  u.PeriodStart,
		PeriodEnd:    u.PeriodEnd,
	}
}

// TokenPersister provides optional async persistence for token usage.
type TokenPersister interface {
	Persist(ctx context.Context, key string, usage TokenUsageSnapshot) error
	Load(ctx context.Context, key string) (*TokenUsageSnapshot, error)
}

// TokenTracker provides fast in-memory token tracking with sharded storage.
type TokenTracker struct {
	shards  [16]tokenShard
	persist TokenPersister // optional async persistence (may be nil)
}

type tokenShard struct {
	mu    sync.RWMutex
	usage map[string]*TokenUsage // key = scope:period:timestamp
}

// NewTokenTracker creates a new token tracker with optional persistence.
func NewTokenTracker(persist TokenPersister) *TokenTracker {
	t := &TokenTracker{
		persist: persist,
	}
	for i := range t.shards {
		t.shards[i].usage = make(map[string]*TokenUsage)
	}
	return t
}

// shardFor returns the shard index for a given key.
func (t *TokenTracker) shardFor(key string) *tokenShard {
	h := fnv.New32a()
	h.Write([]byte(key))
	return &t.shards[h.Sum32()%16]
}

// Check returns whether the request is within budget for the given limit.
func (t *TokenTracker) Check(ctx context.Context, key string, limit *HierarchicalLimit) (bool, *TokenUsageSnapshot, error) {
	usage := t.getOrCreate(key, limit.Period)
	now := time.Now().UTC()

	// Auto-rollover: if current time is past period end, reset counters
	if now.After(usage.PeriodEnd) {
		start, end := periodBounds(limit.Period, now)
		usage.InputTokens.Store(0)
		usage.OutputTokens.Store(0)
		usage.TotalTokens.Store(0)
		usage.PeriodStart = start
		usage.PeriodEnd = end
	}

	snap := usage.Snapshot()

	// Check each limit type (0 means unlimited)
	if limit.InputTokenLimit > 0 && snap.InputTokens >= limit.InputTokenLimit {
		return false, &snap, nil
	}
	if limit.OutputTokenLimit > 0 && snap.OutputTokens >= limit.OutputTokenLimit {
		return false, &snap, nil
	}
	if limit.TotalTokenLimit > 0 && snap.TotalTokens >= limit.TotalTokenLimit {
		return false, &snap, nil
	}

	return true, &snap, nil
}

// Record adds token usage to the tracker.
func (t *TokenTracker) Record(ctx context.Context, key string, period string, inputTokens, outputTokens int64) {
	usage := t.getOrCreate(key, period)
	now := time.Now().UTC()

	// Auto-rollover: if current time is past period end, reset counters
	if now.After(usage.PeriodEnd) {
		start, end := periodBounds(period, now)
		usage.InputTokens.Store(0)
		usage.OutputTokens.Store(0)
		usage.TotalTokens.Store(0)
		usage.PeriodStart = start
		usage.PeriodEnd = end
	}

	usage.InputTokens.Add(inputTokens)
	usage.OutputTokens.Add(outputTokens)
	usage.TotalTokens.Add(inputTokens + outputTokens)

	// Async persistence (fire-and-forget)
	if t.persist != nil {
		snap := usage.Snapshot()
		go func() {
			_ = t.persist.Persist(ctx, key, snap)
		}()
	}
}

// Usage returns current usage snapshot for a key. Returns nil if no usage exists.
func (t *TokenTracker) Usage(_ context.Context, key string) *TokenUsageSnapshot {
	shard := t.shardFor(key)
	shard.mu.RLock()
	u, ok := shard.usage[key]
	shard.mu.RUnlock()
	if !ok {
		return nil
	}
	snap := u.Snapshot()
	return &snap
}

// Reset clears usage for a key.
func (t *TokenTracker) Reset(_ context.Context, key string) {
	shard := t.shardFor(key)
	shard.mu.Lock()
	delete(shard.usage, key)
	shard.mu.Unlock()
}

// getOrCreate returns the TokenUsage for a key, creating it if necessary.
func (t *TokenTracker) getOrCreate(key string, period string) *TokenUsage {
	shard := t.shardFor(key)

	// Fast path: read lock
	shard.mu.RLock()
	if u, ok := shard.usage[key]; ok {
		shard.mu.RUnlock()
		return u
	}
	shard.mu.RUnlock()

	// Slow path: write lock
	shard.mu.Lock()
	defer shard.mu.Unlock()

	// Double-check after acquiring write lock
	if u, ok := shard.usage[key]; ok {
		return u
	}

	now := time.Now().UTC()
	start, end := periodBounds(period, now)
	u := &TokenUsage{
		PeriodStart: start,
		PeriodEnd:   end,
	}
	shard.usage[key] = u
	return u
}

// BuildKey constructs a tracking key from scope values and period.
// The key format is: scope1=val1:scope2=val2:period:timestamp
// Scopes are sorted alphabetically for consistency.
func BuildKey(scopes map[string]string, period string) string {
	if len(scopes) == 0 {
		return "global:" + period + ":" + periodTimestamp(period, time.Now().UTC())
	}

	// Sort scope keys for deterministic key construction
	keys := make([]string, 0, len(scopes))
	for k := range scopes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(scopes[k])
	}
	b.WriteByte(':')
	b.WriteString(period)
	b.WriteByte(':')
	b.WriteString(periodTimestamp(period, time.Now().UTC()))

	return b.String()
}

// BuildKeyAt constructs a tracking key for a specific time (useful for testing).
func BuildKeyAt(scopes map[string]string, period string, at time.Time) string {
	if len(scopes) == 0 {
		return "global:" + period + ":" + periodTimestamp(period, at)
	}

	keys := make([]string, 0, len(scopes))
	for k := range scopes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(scopes[k])
	}
	b.WriteByte(':')
	b.WriteString(period)
	b.WriteByte(':')
	b.WriteString(periodTimestamp(period, at))

	return b.String()
}

// periodBounds returns the start and end of the period containing the given time.
func periodBounds(period string, now time.Time) (time.Time, time.Time) {
	now = now.UTC()
	switch period {
	case "minute":
		start := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), 0, 0, time.UTC)
		return start, start.Add(time.Minute)
	case "hour":
		start := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, time.UTC)
		return start, start.Add(time.Hour)
	case "day":
		start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		return start, start.AddDate(0, 0, 1)
	case "month":
		start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		return start, start.AddDate(0, 1, 0)
	default:
		// Default to day
		start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		return start, start.AddDate(0, 0, 1)
	}
}

// periodTimestamp returns a string timestamp identifying the period bucket.
func periodTimestamp(period string, now time.Time) string {
	now = now.UTC()
	switch period {
	case "minute":
		return fmt.Sprintf("%d%02d%02d%02d%02d", now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute())
	case "hour":
		return fmt.Sprintf("%d%02d%02d%02d", now.Year(), now.Month(), now.Day(), now.Hour())
	case "day":
		return fmt.Sprintf("%d%02d%02d", now.Year(), now.Month(), now.Day())
	case "month":
		return fmt.Sprintf("%d%02d", now.Year(), now.Month())
	default:
		return fmt.Sprintf("%d%02d%02d", now.Year(), now.Month(), now.Day())
	}
}
