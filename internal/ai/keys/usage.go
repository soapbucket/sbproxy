package keys

import (
	"sync"
	"sync/atomic"
	"time"
)

// UsageTracker tracks per-key usage with atomic counters.
type UsageTracker struct {
	entries sync.Map // map[string]*usageEntry
}

type usageEntry struct {
	requests     int64
	inputTokens  int64
	outputTokens int64
	costMicroUSD int64 // microdollars to avoid float atomics
	errors       int64
	periodStart  time.Time
	period       string
}

// NewUsageTracker creates a new per-key usage tracker.
func NewUsageTracker() *UsageTracker {
	return &UsageTracker{}
}

// Record records a request's usage against a virtual key.
func (t *UsageTracker) Record(keyID string, inputTokens, outputTokens int, costUSD float64, isError bool) {
	entry := t.getOrCreate(keyID)
	atomic.AddInt64(&entry.requests, 1)
	atomic.AddInt64(&entry.inputTokens, int64(inputTokens))
	atomic.AddInt64(&entry.outputTokens, int64(outputTokens))
	atomic.AddInt64(&entry.costMicroUSD, int64(costUSD*1_000_000))
	if isError {
		atomic.AddInt64(&entry.errors, 1)
	}
}

// GetUsage returns the current usage for a key.
func (t *UsageTracker) GetUsage(keyID string) *KeyUsage {
	val, ok := t.entries.Load(keyID)
	if !ok {
		return &KeyUsage{KeyID: keyID}
	}
	e := val.(*usageEntry)
	return &KeyUsage{
		KeyID:        keyID,
		Requests:     atomic.LoadInt64(&e.requests),
		InputTokens:  atomic.LoadInt64(&e.inputTokens),
		OutputTokens: atomic.LoadInt64(&e.outputTokens),
		TotalTokens:  atomic.LoadInt64(&e.inputTokens) + atomic.LoadInt64(&e.outputTokens),
		CostUSD:      float64(atomic.LoadInt64(&e.costMicroUSD)) / 1_000_000,
		Errors:       atomic.LoadInt64(&e.errors),
		Period:       e.period,
		PeriodStart:  e.periodStart,
	}
}

// CheckBudget checks if a key has exceeded its budget limit.
// Returns true if within budget, false if exceeded.
func (t *UsageTracker) CheckBudget(keyID string, maxBudgetUSD float64, budgetPeriod string) bool {
	if maxBudgetUSD <= 0 {
		return true // No budget limit
	}

	val, ok := t.entries.Load(keyID)
	if !ok {
		return true // No usage yet
	}
	e := val.(*usageEntry)

	// Check if period has rolled over
	if t.periodExpired(e) {
		t.resetEntry(e)
		return true
	}

	currentCost := float64(atomic.LoadInt64(&e.costMicroUSD)) / 1_000_000
	return currentCost < maxBudgetUSD
}

// CheckTokenBudget checks if a key has exceeded its total token budget.
// Returns true if within budget, false if exceeded.
func (t *UsageTracker) CheckTokenBudget(keyID string, maxTokens int64) bool {
	if maxTokens <= 0 {
		return true // No token limit
	}
	val, ok := t.entries.Load(keyID)
	if !ok {
		return true // No usage yet
	}
	e := val.(*usageEntry)
	if t.periodExpired(e) {
		t.resetEntry(e)
		return true
	}
	total := atomic.LoadInt64(&e.inputTokens) + atomic.LoadInt64(&e.outputTokens)
	return total < maxTokens
}

// TokenUtilization returns the fraction of token budget used (0.0 to 1.0+).
// Returns 0 if no limit or no usage.
func (t *UsageTracker) TokenUtilization(keyID string, maxTokens int64) float64 {
	if maxTokens <= 0 {
		return 0
	}
	val, ok := t.entries.Load(keyID)
	if !ok {
		return 0
	}
	e := val.(*usageEntry)
	total := atomic.LoadInt64(&e.inputTokens) + atomic.LoadInt64(&e.outputTokens)
	return float64(total) / float64(maxTokens)
}

// CheckTokenRate checks if a key is within its tokens-per-minute limit.
func (t *UsageTracker) CheckTokenRate(keyID string, maxTokensPerMin int) bool {
	if maxTokensPerMin <= 0 {
		return true
	}
	usage := t.GetUsage(keyID)
	// Simple check: total tokens in current period.
	// For proper per-minute tracking, a sliding window would be better,
	// but this provides a reasonable approximation for budget enforcement.
	return usage.TotalTokens < int64(maxTokensPerMin)
}

// Reset clears usage for a key.
func (t *UsageTracker) Reset(keyID string) {
	t.entries.Delete(keyID)
}

func (t *UsageTracker) getOrCreate(keyID string) *usageEntry {
	if val, ok := t.entries.Load(keyID); ok {
		e := val.(*usageEntry)
		if t.periodExpired(e) {
			t.resetEntry(e)
		}
		return e
	}

	entry := &usageEntry{
		periodStart: time.Now(),
		period:      "daily", // Default period
	}
	actual, _ := t.entries.LoadOrStore(keyID, entry)
	return actual.(*usageEntry)
}

func (t *UsageTracker) periodExpired(e *usageEntry) bool {
	now := time.Now()
	switch e.period {
	case "daily":
		return now.Sub(e.periodStart) >= 24*time.Hour
	case "monthly":
		return now.Sub(e.periodStart) >= 30*24*time.Hour
	default:
		return false // "total" never expires
	}
}

func (t *UsageTracker) resetEntry(e *usageEntry) {
	atomic.StoreInt64(&e.requests, 0)
	atomic.StoreInt64(&e.inputTokens, 0)
	atomic.StoreInt64(&e.outputTokens, 0)
	atomic.StoreInt64(&e.costMicroUSD, 0)
	atomic.StoreInt64(&e.errors, 0)
	e.periodStart = time.Now()
}
