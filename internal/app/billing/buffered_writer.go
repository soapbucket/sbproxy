// Package billing tracks and reports usage metrics for metered billing.
package billing

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
)

const (
	defaultBufferSize       = 10000
	deadLetterFailThreshold = 3
)

// BufferedWriter wraps any MetricsWriter with a bounded ring buffer.
// On Write failure the records are buffered (up to BufferSize).
// On the next successful Write, buffered records are drained first.
// After deadLetterFailThreshold consecutive failures the oldest buffered
// records are logged as dead-letter entries via slog.Error and discarded.
type BufferedWriter struct {
	inner      MetricsWriter
	mu         sync.Mutex
	ring       []UsageMetric
	bufferSize int
	failures   int // consecutive failure count
}

// NewBufferedWriter wraps inner with a bounded ring buffer.
// If bufferSize <= 0, defaultBufferSize (10 000) is used.
func NewBufferedWriter(inner MetricsWriter, bufferSize int) *BufferedWriter {
	if bufferSize <= 0 {
		bufferSize = defaultBufferSize
	}
	return &BufferedWriter{
		inner:      inner,
		ring:       make([]UsageMetric, 0, min(bufferSize, 1024)), // pre-alloc up to 1k
		bufferSize: bufferSize,
	}
}

// Write attempts to write metrics through the inner writer.
// On success any previously buffered records are drained first.
// On failure records are appended to the ring buffer (bounded).
func (bw *BufferedWriter) Write(ctx context.Context, metrics []UsageMetric) error {
	bw.mu.Lock()
	defer bw.mu.Unlock()

	// Build the full batch: buffered records first, then new ones.
	var batch []UsageMetric
	if len(bw.ring) > 0 {
		batch = make([]UsageMetric, 0, len(bw.ring)+len(metrics))
		batch = append(batch, bw.ring...)
		batch = append(batch, metrics...)
	} else {
		batch = metrics
	}

	err := bw.inner.Write(ctx, batch)
	if err == nil {
		// Success: clear the buffer and reset failure counter.
		bw.ring = bw.ring[:0]
		bw.failures = 0
		return nil
	}

	// Failure path: buffer the new metrics (the old ones are already in bw.ring).
	bw.failures++
	for _, m := range metrics {
		if len(bw.ring) >= bw.bufferSize {
			// Buffer full: evict the oldest record to dead-letter log.
			bw.deadLetter(bw.ring[0])
			bw.ring = bw.ring[1:]
		}
		bw.ring = append(bw.ring, m)
	}

	// After N consecutive failures, flush oldest records to dead-letter log
	// to prevent unbounded memory growth when the backend is down for a long time.
	if bw.failures >= deadLetterFailThreshold && len(bw.ring) > 0 {
		drainCount := len(bw.ring)
		if drainCount > len(metrics) {
			drainCount = len(metrics) // drain roughly the same amount we just added
		}
		for i := 0; i < drainCount && len(bw.ring) > 0; i++ {
			bw.deadLetter(bw.ring[0])
			bw.ring = bw.ring[1:]
		}
		slog.Warn("billing buffered writer: drained records to dead-letter after consecutive failures",
			"consecutive_failures", bw.failures,
			"drained", drainCount,
			"remaining_buffered", len(bw.ring))
	}

	return err
}

// Close flushes any remaining buffered records to the dead-letter log
// and closes the inner writer.
func (bw *BufferedWriter) Close() error {
	bw.mu.Lock()
	if len(bw.ring) > 0 {
		slog.Warn("billing buffered writer closing with buffered records",
			"count", len(bw.ring))
		for _, m := range bw.ring {
			bw.deadLetter(m)
		}
		bw.ring = bw.ring[:0]
	}
	bw.mu.Unlock()
	return bw.inner.Close()
}

// deadLetter logs a single metric record that could not be delivered.
func (bw *BufferedWriter) deadLetter(m UsageMetric) {
	data, err := json.Marshal(m)
	if err != nil {
		slog.Error("billing dead-letter: failed to marshal metric",
			"workspace_id", m.WorkspaceID,
			"origin_id", m.OriginID,
			"error", err)
		return
	}
	slog.Error("billing dead-letter: undeliverable metric record",
		"workspace_id", m.WorkspaceID,
		"origin_id", m.OriginID,
		"period", m.Period,
		"request_count", m.RequestCount,
		"record", string(data))
}
