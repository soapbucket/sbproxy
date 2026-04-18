package events

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewWebhookSubscriber_Defaults(t *testing.T) {
	ws := NewWebhookSubscriber(WebhookConfig{
		URL: "http://localhost:9999/webhook",
	})
	if ws == nil {
		t.Fatal("expected non-nil subscriber")
	}
	if ws.client.Timeout != 10*time.Second {
		t.Errorf("expected default timeout 10s, got %v", ws.client.Timeout)
	}
}

func TestNewWebhookSubscriber_CustomTimeout(t *testing.T) {
	ws := NewWebhookSubscriber(WebhookConfig{
		URL:         "http://localhost:9999/webhook",
		TimeoutSecs: 30,
	})
	if ws.client.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", ws.client.Timeout)
	}
}

func TestWebhookSubscriber_Handle_Success(t *testing.T) {
	var received SystemEvent

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}
		if auth := r.Header.Get("X-Custom-Header"); auth != "custom-value" {
			t.Errorf("expected X-Custom-Header, got %q", auth)
		}

		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&received); err != nil {
			t.Errorf("failed to decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ws := NewWebhookSubscriber(WebhookConfig{
		URL: srv.URL,
		Headers: map[string]string{
			"X-Custom-Header": "custom-value",
		},
	})

	event := SystemEvent{
		Type:     EventCircuitBreakerOpen,
		Severity: SeverityCritical,
		Source:   "test",
		Data:     map[string]interface{}{"origin": "api.example.com"},
	}

	err := ws.Handle(context.Background(), event)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if received.Type != EventCircuitBreakerOpen {
		t.Errorf("expected event type %s, got %s", EventCircuitBreakerOpen, received.Type)
	}
}

func TestWebhookSubscriber_Handle_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ws := NewWebhookSubscriber(WebhookConfig{
		URL: srv.URL,
	})

	err := ws.Handle(context.Background(), SystemEvent{Type: "test"})
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestWebhookSubscriber_Handle_Retry(t *testing.T) {
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ws := NewWebhookSubscriber(WebhookConfig{
		URL:            srv.URL,
		RetryCount:     3,
		RetryDelaySecs: 0, // Will default to 2, but we override the client for speed
	})
	// Override retry delay for fast tests
	ws.config.RetryDelaySecs = 0

	err := ws.Handle(context.Background(), SystemEvent{Type: "test"})
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}

	if got := attempts.Load(); got != 3 {
		t.Errorf("expected 3 attempts, got %d", got)
	}
}

func TestWebhookSubscriber_Handle_AllRetriesFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ws := NewWebhookSubscriber(WebhookConfig{
		URL:            srv.URL,
		RetryCount:     2,
		RetryDelaySecs: 0,
	})
	ws.config.RetryDelaySecs = 0

	err := ws.Handle(context.Background(), SystemEvent{Type: "test"})
	if err == nil {
		t.Fatal("expected error when all retries fail")
	}
}

func TestWebhookSubscriber_HandleEvent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ws := NewWebhookSubscriber(WebhookConfig{URL: srv.URL})

	err := ws.HandleEvent(SystemEvent{
		Type:     EventConfigUpdated,
		Severity: SeverityInfo,
		Source:   "test",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestWebhookSubscriber_Handle_ContextCanceled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ws := NewWebhookSubscriber(WebhookConfig{
		URL:         srv.URL,
		TimeoutSecs: 1,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := ws.Handle(ctx, SystemEvent{Type: "test"})
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
}
