// Package alerting provides alert notification channels and a deduplicating alert manager.
//
// Alerts are fired via the AlertManager, which fans out to all registered Channels.
// Built-in channels include WebhookChannel (HTTP POST) and LogChannel (slog).
// A configurable deduplication window prevents alert storms.
package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// ChannelType identifies the notification channel type.
type ChannelType string

const (
	// ChannelWebhook delivers alerts via HTTP POST.
	ChannelWebhook ChannelType = "webhook"
	// ChannelLog delivers alerts via structured logging.
	ChannelLog ChannelType = "log"
	// ChannelMetric delivers alerts as metric increments.
	ChannelMetric ChannelType = "metric"
)

// ChannelConfig configures a notification channel.
type ChannelConfig struct {
	Type    ChannelType       `json:"type" yaml:"type"`
	URL     string            `json:"url,omitempty" yaml:"url"`
	Headers map[string]string `json:"headers,omitempty" yaml:"headers"`
}

// Alert represents an alert to be sent.
type Alert struct {
	Name      string            `json:"name"`
	Severity  string            `json:"severity"` // "critical", "warning", "info"
	Message   string            `json:"message"`
	Labels    map[string]string `json:"labels,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// Channel is the interface for alert delivery.
type Channel interface {
	Send(ctx context.Context, alert Alert) error
	Type() ChannelType
}

// --- AlertManager ---

// AlertManager manages alert channels and deduplication.
// Alerts with the same name are deduplicated within the configured window:
// if an alert with the same name was sent within the window, the duplicate is silently dropped.
type AlertManager struct {
	mu          sync.RWMutex
	channels    []Channel
	dedup       map[string]time.Time // alert name -> last sent
	dedupWindow time.Duration
}

// NewAlertManager creates a new AlertManager with the given deduplication window.
// If dedupWindow is 0, deduplication is disabled (all alerts are sent).
func NewAlertManager(dedupWindow time.Duration) *AlertManager {
	return &AlertManager{
		channels:    make([]Channel, 0),
		dedup:       make(map[string]time.Time),
		dedupWindow: dedupWindow,
	}
}

// AddChannel registers a notification channel.
func (am *AlertManager) AddChannel(ch Channel) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.channels = append(am.channels, ch)
}

// Fire sends an alert to all registered channels. If the alert was sent
// within the deduplication window, it is silently dropped.
func (am *AlertManager) Fire(ctx context.Context, alert Alert) error {
	if alert.Timestamp.IsZero() {
		alert.Timestamp = time.Now().UTC()
	}

	am.mu.Lock()

	// Check deduplication
	if am.dedupWindow > 0 {
		if lastSent, ok := am.dedup[alert.Name]; ok {
			if time.Since(lastSent) < am.dedupWindow {
				am.mu.Unlock()
				slog.Debug("alert deduplicated",
					"name", alert.Name,
					"last_sent", lastSent)
				return nil
			}
		}
		am.dedup[alert.Name] = time.Now()
	}

	// Copy channels slice under lock to iterate without holding it
	channels := make([]Channel, len(am.channels))
	copy(channels, am.channels)
	am.mu.Unlock()

	var errs []error
	for _, ch := range channels {
		if err := ch.Send(ctx, alert); err != nil {
			slog.Error("alert channel delivery failed",
				"channel_type", ch.Type(),
				"alert_name", alert.Name,
				"error", err)
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("alert delivery failed on %d/%d channels", len(errs), len(channels))
	}
	return nil
}

// --- WebhookChannel ---

// WebhookChannel sends alerts via HTTP POST to a configured URL.
type WebhookChannel struct {
	config ChannelConfig
	client *http.Client
}

// NewWebhookChannel creates a new webhook alert channel.
func NewWebhookChannel(cfg ChannelConfig) *WebhookChannel {
	return &WebhookChannel{
		config: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Send posts the alert as JSON to the webhook URL.
func (wc *WebhookChannel) Send(ctx context.Context, alert Alert) error {
	payload, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("webhook: failed to marshal alert: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wc.config.URL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("webhook: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range wc.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := wc.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: endpoint returned status %d", resp.StatusCode)
	}

	return nil
}

// Type returns the channel type.
func (wc *WebhookChannel) Type() ChannelType {
	return ChannelWebhook
}

// --- LogChannel ---

// LogChannel logs alerts via slog at a level matching the alert severity.
type LogChannel struct{}

// NewLogChannel creates a new log alert channel.
func NewLogChannel() *LogChannel {
	return &LogChannel{}
}

// Send logs the alert using slog.
func (lc *LogChannel) Send(_ context.Context, alert Alert) error {
	level := slog.LevelInfo
	switch alert.Severity {
	case "critical":
		level = slog.LevelError
	case "warning":
		level = slog.LevelWarn
	case "info":
		level = slog.LevelInfo
	}

	slog.Log(context.Background(), level, "alert fired",
		slog.String("name", alert.Name),
		slog.String("severity", alert.Severity),
		slog.String("message", alert.Message),
		slog.Any("labels", alert.Labels),
		slog.Time("timestamp", alert.Timestamp),
	)

	return nil
}

// Type returns the channel type.
func (lc *LogChannel) Type() ChannelType {
	return ChannelLog
}

// --- Alert helper functions ---

// AlertBudgetExhaustion fires a budget exhaustion alert.
// Severity is "critical" if percentUsed >= 100, "warning" otherwise.
func AlertBudgetExhaustion(am *AlertManager, budgetName string, percentUsed float64) {
	severity := "warning"
	if percentUsed >= 100 {
		severity = "critical"
	}

	_ = am.Fire(context.Background(), Alert{
		Name:     fmt.Sprintf("budget_exhaustion:%s", budgetName),
		Severity: severity,
		Message:  fmt.Sprintf("Budget %q is at %.1f%% usage", budgetName, percentUsed),
		Labels: map[string]string{
			"budget":       budgetName,
			"percent_used": fmt.Sprintf("%.1f", percentUsed),
		},
	})
}

// AlertCertExpiry fires a certificate expiry alert.
// Severity is "critical" if daysUntilExpiry <= 7, "warning" otherwise.
func AlertCertExpiry(am *AlertManager, hostname string, daysUntilExpiry int) {
	severity := "warning"
	if daysUntilExpiry <= 7 {
		severity = "critical"
	}

	_ = am.Fire(context.Background(), Alert{
		Name:     fmt.Sprintf("cert_expiry:%s", hostname),
		Severity: severity,
		Message:  fmt.Sprintf("Certificate for %q expires in %d days", hostname, daysUntilExpiry),
		Labels: map[string]string{
			"hostname":         hostname,
			"days_until_expiry": fmt.Sprintf("%d", daysUntilExpiry),
		},
	})
}

// AlertCircuitBreakerTrip fires a circuit breaker state change alert.
// Severity is "critical" when the new state is "open", "info" otherwise.
func AlertCircuitBreakerTrip(am *AlertManager, origin, newState string) {
	severity := "info"
	if newState == "open" {
		severity = "critical"
	}

	_ = am.Fire(context.Background(), Alert{
		Name:     fmt.Sprintf("circuit_breaker:%s", origin),
		Severity: severity,
		Message:  fmt.Sprintf("Circuit breaker for origin %q transitioned to %s", origin, newState),
		Labels: map[string]string{
			"origin":    origin,
			"new_state": newState,
		},
	})
}
