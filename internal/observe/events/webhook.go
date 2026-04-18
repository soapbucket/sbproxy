// Package events implements a publish-subscribe event framework for system observability.
package events

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// WebhookConfig configures webhook event delivery.
type WebhookConfig struct {
	URL            string            `json:"url" yaml:"url"`
	Headers        map[string]string `json:"headers,omitempty" yaml:"headers"`
	TimeoutSecs    int               `json:"timeout_secs,omitempty" yaml:"timeout_secs"`
	RetryCount     int               `json:"retry_count,omitempty" yaml:"retry_count"`
	RetryDelaySecs int               `json:"retry_delay_secs,omitempty" yaml:"retry_delay_secs"`
}

// WebhookSubscriber delivers events via HTTP POST to a configured URL.
// It implements the EventHandler signature so it can be registered with the event bus.
type WebhookSubscriber struct {
	config WebhookConfig
	client *http.Client
}

// NewWebhookSubscriber creates a new webhook subscriber with the given configuration.
// If TimeoutSecs is 0, it defaults to 10 seconds.
// If RetryCount is 0, no retries are attempted.
// If RetryDelaySecs is 0, it defaults to 2 seconds between retries.
func NewWebhookSubscriber(cfg WebhookConfig) *WebhookSubscriber {
	timeout := time.Duration(cfg.TimeoutSecs) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	if cfg.RetryDelaySecs == 0 && cfg.RetryCount > 0 {
		cfg.RetryDelaySecs = 2
	}

	return &WebhookSubscriber{
		config: cfg,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// Handle sends the event payload as JSON to the webhook URL.
// It uses context.Background() since EventHandler does not receive a context.
// On failure, it retries up to RetryCount times with RetryDelaySecs delay.
func (ws *WebhookSubscriber) Handle(ctx context.Context, event interface{}) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("webhook: failed to marshal event: %w", err)
	}

	retryDelay := time.Duration(ws.config.RetryDelaySecs) * time.Second
	maxAttempts := 1 + ws.config.RetryCount

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			// Wait before retry, but respect context cancellation
			timer := time.NewTimer(retryDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}

		lastErr = ws.sendRequest(ctx, payload)
		if lastErr == nil {
			return nil
		}

		slog.Warn("webhook delivery failed",
			"url", ws.config.URL,
			"attempt", attempt+1,
			"max_attempts", maxAttempts,
			"error", lastErr)
	}

	return fmt.Errorf("webhook: all %d attempts failed, last error: %w", maxAttempts, lastErr)
}

// HandleEvent adapts the webhook subscriber to the EventHandler signature
// used by the event bus. This is the function to pass to Subscribe().
func (ws *WebhookSubscriber) HandleEvent(event SystemEvent) error {
	return ws.Handle(context.Background(), event)
}

// sendRequest performs a single HTTP POST to the webhook URL.
func (ws *WebhookSubscriber) sendRequest(ctx context.Context, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ws.config.URL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range ws.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := ws.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}
