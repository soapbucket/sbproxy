package metric

import (
	"log/slog"
	"sync"
)

// --- Default Configuration ---

const (
	// DefaultMaxCardinalityValues is the default maximum number of unique label values
	// allowed per metric before new values are demoted to the "other" bucket.
	DefaultMaxCardinalityValues = 1000

	// DemotedLabelValue is the replacement value used when a label exceeds the cardinality cap.
	DemotedLabelValue = "other"
)

// --- CardinalityLimiter ---

// CardinalityLimiter prevents unbounded label cardinality in Prometheus metrics.
// When a label exceeds MaxValues unique values, new values are mapped to "other".
type CardinalityLimiter struct {
	mu        sync.RWMutex
	maxValues int
	seen      map[string]map[string]struct{} // metric_name -> set of seen values
	demotion  *DemotionLogger
}

// NewCardinalityLimiter creates a limiter with the given max unique values per label.
func NewCardinalityLimiter(maxValues int) *CardinalityLimiter {
	if maxValues <= 0 {
		maxValues = DefaultMaxCardinalityValues
	}
	return &CardinalityLimiter{
		maxValues: maxValues,
		seen:      make(map[string]map[string]struct{}),
		demotion:  newDemotionLogger(),
	}
}

// Limit returns the label value if under the cardinality cap, or "other" if exceeded.
func (cl *CardinalityLimiter) Limit(metricName, labelValue string) string {
	// Fast path: check if the value is already tracked.
	cl.mu.RLock()
	values, metricExists := cl.seen[metricName]
	if metricExists {
		if _, exists := values[labelValue]; exists {
			cl.mu.RUnlock()
			return labelValue
		}
		count := len(values)
		cl.mu.RUnlock()

		// Value is not tracked and we are at or over the cap.
		if count >= cl.maxValues {
			cl.demotion.WarnOnce(metricName, count, cl.maxValues)
			return DemotedLabelValue
		}
	} else {
		cl.mu.RUnlock()
	}

	// Slow path: acquire write lock and add the value.
	cl.mu.Lock()
	defer cl.mu.Unlock()

	// Re-check after acquiring write lock (double-checked locking).
	values, metricExists = cl.seen[metricName]
	if !metricExists {
		values = make(map[string]struct{})
		cl.seen[metricName] = values
	}

	if _, exists := values[labelValue]; exists {
		return labelValue
	}

	if len(values) >= cl.maxValues {
		cl.demotion.WarnOnce(metricName, len(values), cl.maxValues)
		return DemotedLabelValue
	}

	values[labelValue] = struct{}{}
	return labelValue
}

// Reset clears all tracked values (e.g., on config reload).
func (cl *CardinalityLimiter) Reset() {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.seen = make(map[string]map[string]struct{})
	cl.demotion.Reset()
}

// Stats returns the current cardinality counts per metric.
func (cl *CardinalityLimiter) Stats() map[string]int {
	cl.mu.RLock()
	defer cl.mu.RUnlock()
	result := make(map[string]int, len(cl.seen))
	for name, values := range cl.seen {
		result[name] = len(values)
	}
	return result
}

// --- Package-level Singleton ---

var defaultLimiter = NewCardinalityLimiter(DefaultMaxCardinalityValues)

// DefaultCardinalityLimiter returns the package-level singleton CardinalityLimiter.
func DefaultCardinalityLimiter() *CardinalityLimiter {
	return defaultLimiter
}

// LimitCardinality is a convenience function that uses the default limiter.
func LimitCardinality(metricName, labelValue string) string {
	return defaultLimiter.Limit(metricName, labelValue)
}

// ResetCardinality resets the default limiter (e.g., on config reload).
func ResetCardinality() {
	defaultLimiter.Reset()
}

// CardinalityStats returns stats from the default limiter.
func CardinalityStats() map[string]int {
	return defaultLimiter.Stats()
}

// --- DemotionLogger ---

// DemotionLogger logs a warning the first time a metric exceeds its cardinality limit.
// Subsequent demotions for the same metric are silently suppressed to avoid log spam.
type DemotionLogger struct {
	mu     sync.Mutex
	warned map[string]bool
}

func newDemotionLogger() *DemotionLogger {
	return &DemotionLogger{
		warned: make(map[string]bool),
	}
}

// WarnOnce logs a warning the first time a metric exceeds its cardinality limit.
func (dl *DemotionLogger) WarnOnce(metricName string, count, limit int) {
	dl.mu.Lock()
	defer dl.mu.Unlock()

	if dl.warned[metricName] {
		return
	}
	dl.warned[metricName] = true
	slog.Warn("metric label cardinality limit reached, new values demoted to 'other'",
		"metric", metricName,
		"current_count", count,
		"limit", limit,
	)
}

// Reset clears the warned state so warnings can fire again after a config reload.
func (dl *DemotionLogger) Reset() {
	dl.mu.Lock()
	defer dl.mu.Unlock()
	dl.warned = make(map[string]bool)
}
