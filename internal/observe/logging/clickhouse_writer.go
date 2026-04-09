// Package logging handles structured request logging to multiple backends (stdout, ClickHouse, file).
package logging

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/soapbucket/sbproxy/internal/platform/circuitbreaker"
	"github.com/soapbucket/sbproxy/internal/observe/events"
	"github.com/soapbucket/sbproxy/internal/observe/logging/buffer"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

const (
	clickhouseMaxRetries  = 3
	clickhouseBaseBackoff = 500 * time.Millisecond
)

// ClickHouseHTTPWriter writes logs directly to ClickHouse HTTP API
// with batching for optimal performance (Go → ClickHouse best practice)
// Uses a local buffer for resilience when ClickHouse is unavailable
type ClickHouseHTTPWriter struct {
	url             string
	client          *http.Client
	logBuffer       buffer.Buffer                  // Local buffering for resilience
	breaker         *circuitbreaker.CircuitBreaker // Prevents cascading failures
	bufferMu        sync.Mutex
	maxBatchSize    int
	maxBatchBytes   int64
	flushInterval   time.Duration
	stopCh          chan struct{}
	wg              sync.WaitGroup
	droppedCount    atomic.Int64
	flushInProgress atomic.Bool
	degraded        atomic.Bool
}

// ClickHouseWriterConfig configures the HTTP writer
type ClickHouseWriterConfig struct {
	Host          string        // ClickHouse host (e.g., "clickhouse:8123")
	Database      string        // Database name
	Table         string        // Table name
	MaxBatchSize  int           // Maximum records per batch (default: 1000)
	MaxBatchBytes int64         // Maximum bytes per batch (default: 1MB)
	FlushInterval time.Duration // Flush interval (default: 5s)
	Timeout       time.Duration // HTTP request timeout (default: 30s)
	AsyncInsert   bool          // Use ClickHouse async_insert (default: true)

	// Buffer configuration
	BufferType        string // "memory", "file", or "hybrid" (default: "hybrid")
	BufferCapacity    int    // Number of entries for memory buffer (default: 1000)
	BufferMaxBytes    int64  // Max bytes for memory buffer (default: 10MB)
	BufferDiskPath    string // Path for disk spillover (default: "/tmp/soapbucket/clickhouse-buffer")
	BufferMaxDiskSize int64  // Max disk size (default: 1GB)
}

// NewClickHouseHTTPWriter creates a new batching HTTP writer for ClickHouse with local buffering
func NewClickHouseHTTPWriter(config ClickHouseWriterConfig) (*ClickHouseHTTPWriter, error) {
	// Set defaults
	if config.MaxBatchSize == 0 {
		config.MaxBatchSize = 1000
	}
	if config.MaxBatchBytes == 0 {
		config.MaxBatchBytes = 1024 * 1024 // 1MB
	}
	if config.FlushInterval == 0 {
		config.FlushInterval = 5 * time.Second
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.BufferType == "" {
		config.BufferType = "hybrid"
	}
	if config.BufferCapacity == 0 {
		config.BufferCapacity = 1000
	}
	if config.BufferMaxBytes == 0 {
		config.BufferMaxBytes = 10 * 1024 * 1024 // 10MB
	}
	if config.BufferDiskPath == "" {
		config.BufferDiskPath = "/tmp/soapbucket/clickhouse-buffer"
	}
	if config.BufferMaxDiskSize == 0 {
		config.BufferMaxDiskSize = 1024 * 1024 * 1024 // 1GB
	}

	// Build ClickHouse HTTP API URL
	query := fmt.Sprintf("INSERT INTO %s.%s FORMAT JSONEachRow", config.Database, config.Table)

	// Build URL with query parameters
	clickhouseURL := fmt.Sprintf("http://%s/", config.Host)
	params := url.Values{}
	params.Set("query", query)
	params.Set("input_format_skip_unknown_fields", "1")
	params.Set("date_time_input_format", "best_effort")
	if config.AsyncInsert {
		params.Set("async_insert", "1")
		params.Set("wait_for_async_insert", "0")
	}
	clickhouseURL += "?" + params.Encode()

	writer := &ClickHouseHTTPWriter{
		url:           clickhouseURL,
		client:        &http.Client{Timeout: config.Timeout},
		maxBatchSize:  config.MaxBatchSize,
		maxBatchBytes: config.MaxBatchBytes,
		flushInterval: config.FlushInterval,
		stopCh:        make(chan struct{}),
		breaker: circuitbreaker.New(circuitbreaker.Config{
			Name:             "clickhouse",
			FailureThreshold: 5,
			SuccessThreshold: 3,
			Timeout:          30 * time.Second,
		}),
	}

	// Create the appropriate buffer type
	var buf buffer.Buffer
	var err error

	writerFunc := func(ctx context.Context, entries []*buffer.Entry) (int, error) {
		return writer.writeBatch(ctx, entries)
	}

	switch config.BufferType {
	case "memory":
		buf = buffer.NewMemoryBuffer(config.BufferCapacity, config.BufferMaxBytes, writerFunc)
	case "file":
		buf, err = buffer.NewFileBuffer(config.BufferDiskPath, config.BufferMaxDiskSize, writerFunc)
	case "hybrid":
		buf, err = buffer.NewHybridBuffer(
			config.BufferCapacity,
			config.BufferMaxBytes,
			config.BufferDiskPath,
			config.BufferMaxDiskSize,
			writerFunc,
		)
	default:
		return nil, fmt.Errorf("unknown buffer type: %s", config.BufferType)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create buffer: %w", err)
	}

	writer.logBuffer = buf

	// Start background flusher
	writer.wg.Add(1)
	go writer.flushLoop()

	return writer, nil
}

// Write adds a log entry to the local buffer (never blocks)
func (w *ClickHouseHTTPWriter) Write(p []byte) (n int, err error) {
	// Make a copy since the caller might reuse the buffer
	entry := &buffer.Entry{
		Data:      make([]byte, len(p)),
		Timestamp: time.Now(),
		Attempt:   0,
	}
	copy(entry.Data, p)

	// Add to local buffer (never blocks, never loses data)
	if err := w.logBuffer.Write(entry); err != nil {
		slog.Warn("log buffer write failed", "error", err)
		// Don't fail the request - data is still buffered somewhere
	}

	// Check if we should flush
	if w.logBuffer.IsFull() {
		w.triggerFlush()
	}

	return len(p), nil
}

// flushLoop periodically flushes the buffer
func (w *ClickHouseHTTPWriter) flushLoop() {
	defer w.wg.Done()
	ticker := time.NewTicker(w.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			w.triggerFlush()
		case <-w.stopCh:
			// Final flush on shutdown
			w.flush()
			return
		}
	}
}

func (w *ClickHouseHTTPWriter) triggerFlush() {
	if !w.flushInProgress.CompareAndSwap(false, true) {
		return
	}
	go w.flush()
}

// flush triggers a flush of the local buffer to ClickHouse
func (w *ClickHouseHTTPWriter) flush() {
	defer w.flushInProgress.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	flushed, err := w.logBuffer.Flush(ctx)
	if err != nil {
		slog.Error("buffer flush failed", "flushed", flushed, "error", err)
		metric.ClickHouseFlushError(err)
		return
	}

	if flushed > 0 {
		slog.Debug("buffer flushed", "count", flushed)
		metric.ClickHouseFlushed(int64(flushed))
	}
}

// writeBatch sends buffered entries to ClickHouse with exponential backoff + jitter
func (w *ClickHouseHTTPWriter) writeBatch(ctx context.Context, entries []*buffer.Entry) (int, error) {
	if len(entries) == 0 {
		return 0, nil
	}

	batchSize := len(entries)
	var totalBytes int64
	for _, entry := range entries {
		totalBytes += int64(len(entry.Data))
	}

	// Build request body (NDJSON format)
	body := w.buildRequestBody(entries)
	if len(body) == 0 {
		return 0, fmt.Errorf("failed to build clickhouse request body")
	}

	// Use circuit breaker to prevent cascading failures
	err := w.breaker.Call(func() error {
		return w.sendBatchWithRetry(ctx, body, batchSize, totalBytes)
	})

	if err == circuitbreaker.ErrCircuitOpen {
		slog.Warn("ClickHouse circuit breaker open, buffering locally",
			"batch_size", batchSize)
		metric.ClickHouseCircuitOpen()

		// Emit event
		events.Publish(events.SystemEvent{
			Type:      events.EventClickHouseDown,
			Severity:  events.SeverityWarning,
			Timestamp: time.Now(),
			Source:    "clickhouse_writer",
			Data: map[string]interface{}{
				"batch_size": batchSize,
				"reason":     "circuit_breaker_open",
			},
		})
		w.degraded.Store(true)

		// Circuit is open but we still have the data in buffer
		// It will be retried when circuit recovers
		return 0, fmt.Errorf("circuit breaker open")
	}

	if err != nil {
		dropped := w.droppedCount.Add(int64(batchSize))
		slog.Error("ClickHouse write failed after retries",
			"batch_size", batchSize,
			"total_dropped", dropped,
			"error", err)
		metric.ClickHouseDropped(int64(batchSize))

		// Emit error event
		events.Publish(events.SystemEvent{
			Type:      events.EventClickHouseFlushError,
			Severity:  events.SeverityCritical,
			Timestamp: time.Now(),
			Source:    "clickhouse_writer",
			Data: map[string]interface{}{
				"batch_size": batchSize,
				"error":      err.Error(),
			},
		})
		w.degraded.Store(true)

		return 0, err
	}

	metric.LogVolume("request", "", "")

	// Emit success event
	events.Publish(events.SystemEvent{
		Type:      events.EventClickHouseFlushSuccess,
		Severity:  events.SeverityInfo,
		Timestamp: time.Now(),
		Source:    "clickhouse_writer",
		Data: map[string]interface{}{
			"batch_size": batchSize,
		},
	})
	if w.degraded.CompareAndSwap(true, false) {
		events.Publish(events.SystemEvent{
			Type:      events.EventClickHouseUp,
			Severity:  events.SeverityInfo,
			Timestamp: time.Now(),
			Source:    "clickhouse_writer",
			Data: map[string]interface{}{
				"batch_size": batchSize,
			},
		})
	}

	return batchSize, nil
}

// sendBatchWithRetry sends with exponential backoff + jitter
func (w *ClickHouseHTTPWriter) sendBatchWithRetry(ctx context.Context, body []byte, batchSize int, batchBytes int64) error {
	for attempt := 0; attempt <= clickhouseMaxRetries; attempt++ {
		if attempt > 0 {
			backoff := calculateBackoff(attempt)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		err := w.sendBatch(ctx, body, batchSize, batchBytes)
		if err == nil {
			return nil
		}

		slog.Warn("ClickHouse send failed",
			"attempt", attempt+1,
			"max_retries", clickhouseMaxRetries,
			"batch_size", batchSize,
			"error", err)
	}
	events.Publish(events.SystemEvent{
		Type:      events.EventClickHouseMaxRetriesExceeded,
		Severity:  events.SeverityError,
		Timestamp: time.Now(),
		Source:    "clickhouse_writer",
		Data: map[string]interface{}{
			"batch_size":  batchSize,
			"batch_bytes": batchBytes,
			"max_retries": clickhouseMaxRetries,
		},
	})
	return fmt.Errorf("max retries exceeded for batch of %d entries", batchSize)
}

// buildRequestBody compresses batch entries into a gzipped NDJSON body
func (w *ClickHouseHTTPWriter) buildRequestBody(entries []*buffer.Entry) []byte {
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	for _, entry := range entries {
		data := bytes.TrimSuffix(entry.Data, []byte{'\n'})
		if _, err := gzWriter.Write(data); err != nil {
			slog.Error("failed to write gzip payload", "error", err)
			return nil
		}
		if _, err := gzWriter.Write([]byte{'\n'}); err != nil {
			slog.Error("failed to write gzip newline", "error", err)
			return nil
		}
	}
	if err := gzWriter.Close(); err != nil {
		slog.Error("failed to finalize gzip payload", "error", err)
		return nil
	}
	return buf.Bytes()
}

// sendBatch sends a compressed batch to ClickHouse, returning an error on failure
func (w *ClickHouseHTTPWriter) sendBatch(ctx context.Context, body []byte, batchSize int, batchBytes int64) error {
	req, err := http.NewRequestWithContext(ctx, "POST", w.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("Content-Encoding", "gzip")

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		return fmt.Errorf("HTTP %d (batch: %d records, %d bytes): %s",
			resp.StatusCode, batchSize, batchBytes, string(respBody))
	}

	return nil
}

// calculateBackoff computes exponential backoff with jitter
func calculateBackoff(attempt int) time.Duration {
	const (
		initialDelay = 100 * time.Millisecond
		maxDelay     = 30 * time.Second
		multiplier   = 2.0
		jitter       = 0.1
	)

	// Exponential: 100ms, 200ms, 400ms, 800ms, ...
	delay := time.Duration(float64(initialDelay) * math.Pow(multiplier, float64(attempt)))

	// Cap at max
	if delay > maxDelay {
		delay = maxDelay
	}

	// Add jitter: ±10%
	jitterAmount := time.Duration(float64(delay) * jitter * (2*rand.Float64() - 1))

	return delay + jitterAmount
}

// DroppedCount returns the total number of log entries dropped due to write failures
func (w *ClickHouseHTTPWriter) DroppedCount() int64 {
	return w.droppedCount.Load()
}

// Close stops the flusher and flushes remaining logs
func (w *ClickHouseHTTPWriter) Close() error {
	close(w.stopCh)
	w.wg.Wait()
	if w.logBuffer != nil {
		return w.logBuffer.Close()
	}
	return nil
}

// MultiWriter creates an io.Writer that writes to both stdout and ClickHouse
func NewClickHouseMultiWriter(clickhouseWriter io.Writer) io.Writer {
	// Write to both stdout (for Fluent Bit/Elasticsearch) and ClickHouse
	return io.MultiWriter(clickhouseWriter)
}
