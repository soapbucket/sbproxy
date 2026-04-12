// Package observability provides webhook-based observability hooks for AI request logging.
package observability

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	json "github.com/goccy/go-json"
)

// AIRequestLog is the structured log entry sent to observability hooks.
type AIRequestLog struct {
	RequestID    string            `json:"request_id"`
	Timestamp    time.Time         `json:"timestamp"`
	Provider     string            `json:"provider"`
	Model        string            `json:"model"`
	InputTokens  int               `json:"input_tokens"`
	OutputTokens int               `json:"output_tokens"`
	CostUSD      float64           `json:"cost_usd,omitempty"`
	LatencyMS    int64             `json:"latency_ms"`
	TTFTMS       int64             `json:"ttft_ms,omitempty"`
	CacheStatus  string            `json:"cache_status,omitempty"`
	StatusCode   int               `json:"status_code"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	Streaming    bool              `json:"streaming"`
}

// Hook is an interface for observability destinations that receive AI request logs.
type Hook interface {
	Name() string
	Send(ctx context.Context, log *AIRequestLog) error
	Close() error
}

// WebhookConfig configures a webhook hook.
type WebhookConfig struct {
	Type            string            `json:"type"`
	URL             string            `json:"url"`
	Headers         map[string]string `json:"headers,omitempty"`
	BatchSize       int               `json:"batch_size,omitempty"`
	FlushIntervalMS int               `json:"flush_interval_ms,omitempty"`
}

// WebhookHook sends AI request logs to a configured URL in batches.
type WebhookHook struct {
	url           string
	headers       map[string]string
	client        *http.Client
	batch         []*AIRequestLog
	mu            sync.Mutex
	maxBatch      int
	flushInterval time.Duration
	stopCh        chan struct{}
	done          chan struct{}
}

// NewWebhookHook creates a new webhook hook from config.
func NewWebhookHook(cfg WebhookConfig) (*WebhookHook, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("observability webhook: url is required")
	}

	maxBatch := cfg.BatchSize
	if maxBatch <= 0 {
		maxBatch = 100
	}

	flushInterval := time.Duration(cfg.FlushIntervalMS) * time.Millisecond
	if flushInterval <= 0 {
		flushInterval = 5 * time.Second
	}

	h := &WebhookHook{
		url:           cfg.URL,
		headers:       cfg.Headers,
		client:        &http.Client{Timeout: 10 * time.Second},
		batch:         make([]*AIRequestLog, 0, maxBatch),
		maxBatch:      maxBatch,
		flushInterval: flushInterval,
		stopCh:        make(chan struct{}),
		done:          make(chan struct{}),
	}

	go h.flushLoop()
	return h, nil
}

// Name returns the hook name.
func (w *WebhookHook) Name() string { return "webhook" }

// Send adds a log entry to the batch buffer. If the batch is full, it flushes immediately.
func (w *WebhookHook) Send(_ context.Context, log *AIRequestLog) error {
	w.mu.Lock()
	w.batch = append(w.batch, log)
	shouldFlush := len(w.batch) >= w.maxBatch
	w.mu.Unlock()

	if shouldFlush {
		w.flush()
	}
	return nil
}

// Close flushes remaining entries and stops the background flush loop.
func (w *WebhookHook) Close() error {
	close(w.stopCh)
	<-w.done
	w.flush()
	return nil
}

// flushLoop runs the periodic flush in the background.
func (w *WebhookHook) flushLoop() {
	defer close(w.done)
	ticker := time.NewTicker(w.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			w.flush()
		case <-w.stopCh:
			return
		}
	}
}

// flush sends all buffered entries to the webhook URL.
func (w *WebhookHook) flush() {
	w.mu.Lock()
	if len(w.batch) == 0 {
		w.mu.Unlock()
		return
	}
	entries := w.batch
	w.batch = make([]*AIRequestLog, 0, w.maxBatch)
	w.mu.Unlock()

	body, err := json.Marshal(entries)
	if err != nil {
		slog.Error("observability webhook: marshal failed", "error", err)
		return
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		slog.Error("observability webhook: create request failed", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		slog.Error("observability webhook: send failed", "error", err, "url", w.url, "entries", len(entries))
		return
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		slog.Warn("observability webhook: non-success response", "status", resp.StatusCode, "url", w.url, "entries", len(entries))
	}
}

// BatchLen returns the current number of buffered entries. Intended for testing.
func (w *WebhookHook) BatchLen() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.batch)
}
