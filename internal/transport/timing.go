// timing.go records per-stage latency measurements using a fixed-size stack-allocated array.
package transport

import (
	"strings"
	"time"
)

// maxTimingStages is the fixed capacity of the stages array.
// Using a fixed-size array keeps TimingCollector on the stack.
const maxTimingStages = 8

// timingEntry records the name and duration of a single processing stage.
type timingEntry struct {
	name     string
	duration time.Duration
}

// TimingCollector records per-stage latency measurements using a fixed-size
// array so that it can be stack-allocated with zero heap allocations in the
// common case (fewer than 8 stages).
type TimingCollector struct {
	stages [maxTimingStages]timingEntry
	count  int
}

// NewTimingCollector returns a ready-to-use collector.
func NewTimingCollector() *TimingCollector {
	return &TimingCollector{}
}

// Record adds a stage measurement. Stages beyond the fixed capacity are silently
// dropped to avoid any allocation.
func (tc *TimingCollector) Record(name string, d time.Duration) {
	if tc.count >= maxTimingStages {
		return
	}
	tc.stages[tc.count] = timingEntry{name: name, duration: d}
	tc.count++
}

// Header formats all recorded stages as a semicolon-separated timing header
// value, e.g. "policy=45us;auth=12us;overhead=57us". Returns an empty string
// when no stages have been recorded.
func (tc *TimingCollector) Header() string {
	if tc.count == 0 {
		return ""
	}

	var b strings.Builder
	for i := 0; i < tc.count; i++ {
		if i > 0 {
			b.WriteByte(';')
		}
		b.WriteString(tc.stages[i].name)
		b.WriteByte('=')
		b.WriteString(tc.stages[i].duration.String())
	}
	return b.String()
}
