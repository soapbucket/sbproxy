package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	json "github.com/goccy/go-json"
)

func TestNewWebhookHook_RequiresURL(t *testing.T) {
	_, err := NewWebhookHook(WebhookConfig{})
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestNewWebhookHook_Defaults(t *testing.T) {
	h, err := NewWebhookHook(WebhookConfig{URL: "http://localhost/hook"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer h.Close()

	if h.maxBatch != 100 {
		t.Errorf("maxBatch = %d, want 100", h.maxBatch)
	}
	if h.flushInterval != 5*time.Second {
		t.Errorf("flushInterval = %v, want 5s", h.flushInterval)
	}
}

func TestWebhookHook_BatchAndFlush(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var logs []*AIRequestLog
		if err := json.NewDecoder(r.Body).Decode(&logs); err != nil {
			t.Errorf("decode failed: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received.Add(int32(len(logs)))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	h, err := NewWebhookHook(WebhookConfig{
		URL:             srv.URL,
		BatchSize:       3,
		FlushIntervalMS: 50,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()
	log := &AIRequestLog{
		RequestID:    "req-1",
		Timestamp:    time.Now(),
		Provider:     "openai",
		Model:        "gpt-4o",
		InputTokens:  100,
		OutputTokens: 50,
		StatusCode:   200,
	}

	// Send 2 entries (below batch size) - should not flush yet
	_ = h.Send(ctx, log)
	_ = h.Send(ctx, log)
	if h.BatchLen() != 2 {
		t.Errorf("batch len = %d after 2 sends, want 2", h.BatchLen())
	}

	// Send 1 more to hit batch size - triggers flush
	_ = h.Send(ctx, log)

	// Allow some time for async flush
	time.Sleep(100 * time.Millisecond)

	if got := received.Load(); got != 3 {
		t.Errorf("received %d entries after batch-triggered flush, want 3", got)
	}
	if h.BatchLen() != 0 {
		t.Errorf("batch len = %d after flush, want 0", h.BatchLen())
	}
}

func TestWebhookHook_TimerFlush(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var logs []*AIRequestLog
		if err := json.NewDecoder(r.Body).Decode(&logs); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received.Add(int32(len(logs)))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	h, err := NewWebhookHook(WebhookConfig{
		URL:             srv.URL,
		BatchSize:       100, // high batch size, should not trigger batch flush
		FlushIntervalMS: 50,  // short interval for testing
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()
	_ = h.Send(ctx, &AIRequestLog{RequestID: "req-timer-1", StatusCode: 200})

	// Wait for timer-based flush
	time.Sleep(200 * time.Millisecond)

	if got := received.Load(); got != 1 {
		t.Errorf("received %d entries after timer flush, want 1", got)
	}

	h.Close()
}

func TestWebhookHook_CloseFlushesRemaining(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var logs []*AIRequestLog
		if err := json.NewDecoder(r.Body).Decode(&logs); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received.Add(int32(len(logs)))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	h, err := NewWebhookHook(WebhookConfig{
		URL:             srv.URL,
		BatchSize:       100,           // won't trigger batch flush
		FlushIntervalMS: 60000,         // 60s, won't trigger timer flush during test
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()
	_ = h.Send(ctx, &AIRequestLog{RequestID: "req-close-1", StatusCode: 200})
	_ = h.Send(ctx, &AIRequestLog{RequestID: "req-close-2", StatusCode: 200})

	// Close should flush remaining
	h.Close()

	if got := received.Load(); got != 2 {
		t.Errorf("received %d entries after close, want 2", got)
	}
}

func TestWebhookHook_CustomHeaders(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	h, err := NewWebhookHook(WebhookConfig{
		URL:             srv.URL,
		Headers:         map[string]string{"Authorization": "Bearer secret"},
		BatchSize:       1,
		FlushIntervalMS: 50,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer h.Close()

	_ = h.Send(context.Background(), &AIRequestLog{RequestID: "req-hdr", StatusCode: 200})
	time.Sleep(100 * time.Millisecond)

	if gotAuth != "Bearer secret" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer secret")
	}
}

func TestWebhookHook_Name(t *testing.T) {
	h, err := NewWebhookHook(WebhookConfig{URL: "http://localhost/hook"})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	if h.Name() != "webhook" {
		t.Errorf("Name() = %q, want %q", h.Name(), "webhook")
	}
}
