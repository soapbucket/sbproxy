// Package billing tracks and reports usage metrics for metered billing.
package billing

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// billingKey represents a unique billing metric identifier
type billingKey struct {
	WorkspaceID string
	OriginID    string
}

// String returns the string representation of the billing key
func (b billingKey) String() string {
	return fmt.Sprintf("%s:%s", b.WorkspaceID, b.OriginID)
}

// UsageMetric represents a single metering record
type UsageMetric struct {
	WorkspaceID    string    `json:"workspace_id"`
	OriginID       string    `json:"origin_id"`
	OriginHostname string    `json:"origin_hostname"`
	ProviderName   string    `json:"provider_name,omitempty"` // for AI providers
	Status         string    `json:"status"`                  // "200", "404", "error"
	RequestCount   int64     `json:"request_count"`
	BytesIn        int64     `json:"bytes_in"`        // client to proxy
	BytesOut       int64     `json:"bytes_out"`       // proxy to client
	BytesBackend   int64     `json:"bytes_backend"`   // proxy to backend (only if not from cache)
	BytesFromCache int64     `json:"bytes_from_cache"` // served from cache (no backend cost)
	TokensUsed     int64     `json:"tokens_used"`     // for AI providers
	ErrorCount     int64     `json:"error_count"`
	Latency        float64   `json:"latency_seconds"` // average
	Period         time.Time `json:"period"`          // hourly bucket
}

// Meter tracks usage metrics in memory with periodic flushing
type Meter struct {
	mu       sync.RWMutex
	metrics  map[billingKey]*UsageMetric // key: workspace_id:origin_id struct
	writer   MetricsWriter
	interval time.Duration
	cancel   context.CancelFunc
}

// MetricsWriter handles writing metrics to backend
type MetricsWriter interface {
	Write(ctx context.Context, metrics []UsageMetric) error
	Close() error
}

// NewMeter creates a new meter with periodic flush
func NewMeter(writer MetricsWriter, flushInterval time.Duration) *Meter {
	if flushInterval == 0 {
		flushInterval = 5 * time.Minute // default
	}

	m := &Meter{
		metrics:  make(map[billingKey]*UsageMetric),
		writer:   writer,
		interval: flushInterval,
	}

	return m
}

// Start begins periodic flushing of metrics
func (m *Meter) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	go func() {
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				// Final flush of accumulated metrics before exiting the loop.
				// Use a fresh context since ctx is already cancelled.
				flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
				if err := m.Flush(flushCtx); err != nil {
					// Log is not available here; Stop() will attempt another flush.
					_ = err
				}
				flushCancel()
				return
			case <-ticker.C:
				_ = m.Flush(ctx)
			}
		}
	}()
}

// Record adds/updates a usage metric
func (m *Meter) Record(metric *UsageMetric) {
	// Normalize to hourly bucket
	metric.Period = metric.Period.Truncate(time.Hour)

	// Use struct key for type-safe billing metric identification
	key := billingKey{WorkspaceID: metric.WorkspaceID, OriginID: metric.OriginID}

	m.mu.Lock()
	defer m.mu.Unlock()

	existing, ok := m.metrics[key]
	if !ok {
		m.metrics[key] = &UsageMetric{
			WorkspaceID:    metric.WorkspaceID,
			OriginID:       metric.OriginID,
			OriginHostname: metric.OriginHostname,
			ProviderName:   metric.ProviderName,
			Period:         metric.Period,
		}
		existing = m.metrics[key]
	}

	// Accumulate metrics
	existing.RequestCount += metric.RequestCount
	existing.BytesIn += metric.BytesIn
	existing.BytesOut += metric.BytesOut
	existing.BytesBackend += metric.BytesBackend
	existing.BytesFromCache += metric.BytesFromCache
	existing.TokensUsed += metric.TokensUsed
	existing.ErrorCount += metric.ErrorCount

	// Update latency (rolling average)
	if existing.Latency == 0 {
		existing.Latency = metric.Latency
	} else {
		existing.Latency = (existing.Latency + metric.Latency) / 2
	}
}

// Flush writes all accumulated metrics to backend
func (m *Meter) Flush(ctx context.Context) error {
	m.mu.Lock()
	metrics := make([]UsageMetric, 0, len(m.metrics))
	for _, v := range m.metrics {
		metrics = append(metrics, *v)
	}
	m.metrics = make(map[billingKey]*UsageMetric) // clear
	m.mu.Unlock()

	if len(metrics) == 0 {
		return nil
	}

	return m.writer.Write(ctx, metrics)
}

// Stop gracefully stops the meter
func (m *Meter) Stop(ctx context.Context) error {
	if m.cancel != nil {
		m.cancel()
	}

	// Final flush
	if err := m.Flush(ctx); err != nil {
		return err
	}

	return m.writer.Close()
}

// CompositeWriter writes to multiple backends
type CompositeWriter struct {
	writers []MetricsWriter
}

// NewCompositeWriter creates a writer that writes to multiple backends
func NewCompositeWriter(writers ...MetricsWriter) *CompositeWriter {
	return &CompositeWriter{writers: writers}
}

// Write writes metrics to all backends
func (cw *CompositeWriter) Write(ctx context.Context, metrics []UsageMetric) error {
	for _, w := range cw.writers {
		if err := w.Write(ctx, metrics); err != nil {
			return err
		}
	}
	return nil
}

// Close closes all writers
func (cw *CompositeWriter) Close() error {
	for _, w := range cw.writers {
		if err := w.Close(); err != nil {
			return err
		}
	}
	return nil
}

// NoopWriter is a no-op implementation for testing
type NoopWriter struct{}

// Write performs the write operation on the NoopWriter.
func (nw *NoopWriter) Write(ctx context.Context, metrics []UsageMetric) error {
	return nil
}

// Close releases resources held by the NoopWriter.
func (nw *NoopWriter) Close() error {
	return nil
}
