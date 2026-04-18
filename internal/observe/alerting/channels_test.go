package alerting

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// --- AlertManager tests ---

func TestNewAlertManager(t *testing.T) {
	am := NewAlertManager(5 * time.Minute)
	if am == nil {
		t.Fatal("expected non-nil alert manager")
	}
	if am.dedupWindow != 5*time.Minute {
		t.Errorf("expected dedup window 5m, got %v", am.dedupWindow)
	}
}

func TestAlertManager_Fire_NoChannels(t *testing.T) {
	am := NewAlertManager(0)
	err := am.Fire(context.Background(), Alert{
		Name:     "test",
		Severity: "info",
		Message:  "test alert",
	})
	if err != nil {
		t.Errorf("expected no error with no channels, got %v", err)
	}
}

func TestAlertManager_Fire_WithLogChannel(t *testing.T) {
	am := NewAlertManager(0)
	am.AddChannel(NewLogChannel())

	err := am.Fire(context.Background(), Alert{
		Name:     "test",
		Severity: "warning",
		Message:  "test alert",
		Labels:   map[string]string{"env": "test"},
	})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestAlertManager_Deduplication(t *testing.T) {
	var mu sync.Mutex
	var sendCount int

	ch := &mockChannel{
		sendFn: func(ctx context.Context, alert Alert) error {
			mu.Lock()
			sendCount++
			mu.Unlock()
			return nil
		},
	}

	am := NewAlertManager(1 * time.Hour)
	am.AddChannel(ch)

	alert := Alert{
		Name:     "dedup-test",
		Severity: "info",
		Message:  "should be deduplicated",
	}

	// Fire the same alert 3 times
	for i := 0; i < 3; i++ {
		_ = am.Fire(context.Background(), alert)
	}

	mu.Lock()
	if sendCount != 1 {
		t.Errorf("expected 1 send (deduplicated), got %d", sendCount)
	}
	mu.Unlock()
}

func TestAlertManager_NoDedupWhenWindowZero(t *testing.T) {
	var mu sync.Mutex
	var sendCount int

	ch := &mockChannel{
		sendFn: func(ctx context.Context, alert Alert) error {
			mu.Lock()
			sendCount++
			mu.Unlock()
			return nil
		},
	}

	am := NewAlertManager(0) // No dedup
	am.AddChannel(ch)

	alert := Alert{Name: "no-dedup", Severity: "info", Message: "test"}
	for i := 0; i < 3; i++ {
		_ = am.Fire(context.Background(), alert)
	}

	mu.Lock()
	if sendCount != 3 {
		t.Errorf("expected 3 sends (no dedup), got %d", sendCount)
	}
	mu.Unlock()
}

func TestAlertManager_TimestampDefault(t *testing.T) {
	var received Alert
	ch := &mockChannel{
		sendFn: func(ctx context.Context, alert Alert) error {
			received = alert
			return nil
		},
	}

	am := NewAlertManager(0)
	am.AddChannel(ch)

	_ = am.Fire(context.Background(), Alert{
		Name:    "ts-test",
		Message: "test",
	})

	if received.Timestamp.IsZero() {
		t.Error("expected timestamp to be populated")
	}
}

// --- WebhookChannel tests ---

func TestWebhookChannel_Send_Success(t *testing.T) {
	var received Alert

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer secret" {
			t.Errorf("expected Authorization header, got %q", auth)
		}

		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&received); err != nil {
			t.Errorf("failed to decode: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ch := NewWebhookChannel(ChannelConfig{
		Type: ChannelWebhook,
		URL:  srv.URL,
		Headers: map[string]string{
			"Authorization": "Bearer secret",
		},
	})

	err := ch.Send(context.Background(), Alert{
		Name:     "webhook-test",
		Severity: "critical",
		Message:  "server down",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if received.Name != "webhook-test" {
		t.Errorf("expected name webhook-test, got %s", received.Name)
	}
}

func TestWebhookChannel_Send_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ch := NewWebhookChannel(ChannelConfig{URL: srv.URL})
	err := ch.Send(context.Background(), Alert{Name: "test"})
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestWebhookChannel_Type(t *testing.T) {
	ch := NewWebhookChannel(ChannelConfig{})
	if ch.Type() != ChannelWebhook {
		t.Errorf("expected type %s, got %s", ChannelWebhook, ch.Type())
	}
}

// --- LogChannel tests ---

func TestLogChannel_Send(t *testing.T) {
	ch := NewLogChannel()
	err := ch.Send(context.Background(), Alert{
		Name:     "log-test",
		Severity: "critical",
		Message:  "test alert",
	})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestLogChannel_Type(t *testing.T) {
	ch := NewLogChannel()
	if ch.Type() != ChannelLog {
		t.Errorf("expected type %s, got %s", ChannelLog, ch.Type())
	}
}

// --- Alert helper tests ---

func TestAlertBudgetExhaustion_Warning(t *testing.T) {
	var received Alert
	ch := &mockChannel{
		sendFn: func(ctx context.Context, alert Alert) error {
			received = alert
			return nil
		},
	}

	am := NewAlertManager(0)
	am.AddChannel(ch)

	AlertBudgetExhaustion(am, "monthly-compute", 85.5)
	if received.Severity != "warning" {
		t.Errorf("expected severity warning for 85.5%%, got %s", received.Severity)
	}
}

func TestAlertBudgetExhaustion_Critical(t *testing.T) {
	var received Alert
	ch := &mockChannel{
		sendFn: func(ctx context.Context, alert Alert) error {
			received = alert
			return nil
		},
	}

	am := NewAlertManager(0)
	am.AddChannel(ch)

	AlertBudgetExhaustion(am, "monthly-compute", 100.0)
	if received.Severity != "critical" {
		t.Errorf("expected severity critical for 100%%, got %s", received.Severity)
	}
}

func TestAlertCertExpiry_Warning(t *testing.T) {
	var received Alert
	ch := &mockChannel{
		sendFn: func(ctx context.Context, alert Alert) error {
			received = alert
			return nil
		},
	}

	am := NewAlertManager(0)
	am.AddChannel(ch)

	AlertCertExpiry(am, "example.com", 14)
	if received.Severity != "warning" {
		t.Errorf("expected severity warning for 14 days, got %s", received.Severity)
	}
}

func TestAlertCertExpiry_Critical(t *testing.T) {
	var received Alert
	ch := &mockChannel{
		sendFn: func(ctx context.Context, alert Alert) error {
			received = alert
			return nil
		},
	}

	am := NewAlertManager(0)
	am.AddChannel(ch)

	AlertCertExpiry(am, "example.com", 3)
	if received.Severity != "critical" {
		t.Errorf("expected severity critical for 3 days, got %s", received.Severity)
	}
}

func TestAlertCircuitBreakerTrip_Open(t *testing.T) {
	var received Alert
	ch := &mockChannel{
		sendFn: func(ctx context.Context, alert Alert) error {
			received = alert
			return nil
		},
	}

	am := NewAlertManager(0)
	am.AddChannel(ch)

	AlertCircuitBreakerTrip(am, "api-backend", "open")
	if received.Severity != "critical" {
		t.Errorf("expected severity critical for open state, got %s", received.Severity)
	}
	if received.Labels["origin"] != "api-backend" {
		t.Errorf("expected origin label api-backend, got %s", received.Labels["origin"])
	}
}

func TestAlertCircuitBreakerTrip_Closed(t *testing.T) {
	var received Alert
	ch := &mockChannel{
		sendFn: func(ctx context.Context, alert Alert) error {
			received = alert
			return nil
		},
	}

	am := NewAlertManager(0)
	am.AddChannel(ch)

	AlertCircuitBreakerTrip(am, "api-backend", "closed")
	if received.Severity != "info" {
		t.Errorf("expected severity info for closed state, got %s", received.Severity)
	}
}

// --- mock channel ---

type mockChannel struct {
	sendFn func(ctx context.Context, alert Alert) error
}

func (m *mockChannel) Send(ctx context.Context, alert Alert) error {
	if m.sendFn != nil {
		return m.sendFn(ctx, alert)
	}
	return nil
}

func (m *mockChannel) Type() ChannelType {
	return "mock"
}
