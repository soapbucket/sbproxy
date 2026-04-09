package logging

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/events"
	"github.com/soapbucket/sbproxy/internal/observe/logging/buffer"
)

func newTestWriter(t *testing.T, serverURL string) *ClickHouseHTTPWriter {
	t.Helper()
	parsed, err := url.Parse(serverURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	writer, err := NewClickHouseHTTPWriter(ClickHouseWriterConfig{
		Host:           parsed.Host,
		Database:       "testdb",
		Table:          "logs",
		BufferType:     "memory",
		BufferCapacity: 8,
		BufferMaxBytes: 1024,
		FlushInterval:  time.Hour,
		Timeout:        time.Second,
	})
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	return writer
}

func TestClickHouseWriter_EmitsMaxRetriesExceeded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	bus := events.NewInProcessEventBus(8)
	defer bus.Close()
	originalBus := events.GetBus()
	events.SetBus(bus)
	defer events.SetBus(originalBus)

	var retriesExceeded atomic.Int32
	events.Subscribe(events.EventClickHouseMaxRetriesExceeded, func(event events.SystemEvent) error {
		retriesExceeded.Add(1)
		return nil
	})

	writer := newTestWriter(t, server.URL)
	defer writer.Close()

	err := writer.sendBatchWithRetry(context.Background(), []byte("payload"), 1, 7)
	if err == nil {
		t.Fatal("expected retries exceeded error")
	}
	time.Sleep(10 * time.Millisecond)
	if retriesExceeded.Load() == 0 {
		t.Fatal("expected clickhouse_max_retries_exceeded event")
	}
}

func TestClickHouseWriter_EmitsClickHouseUpOnRecovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	bus := events.NewInProcessEventBus(8)
	defer bus.Close()
	originalBus := events.GetBus()
	events.SetBus(bus)
	defer events.SetBus(originalBus)

	var up atomic.Int32
	events.Subscribe(events.EventClickHouseUp, func(event events.SystemEvent) error {
		up.Add(1)
		return nil
	})

	writer := newTestWriter(t, server.URL)
	defer writer.Close()
	writer.degraded.Store(true)

	_, err := writer.writeBatch(context.Background(), []*buffer.Entry{{Data: []byte(`{"a":1}`), Timestamp: time.Now()}})
	if err != nil {
		t.Fatalf("writeBatch error: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if up.Load() == 0 {
		t.Fatal("expected clickhouse_up event")
	}
}
