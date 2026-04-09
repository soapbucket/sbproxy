package adapters

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai/callbacks"
)

// WebhookCallback sends JSON payloads to a generic webhook URL
// with optional custom headers and HMAC-SHA256 signing.
type WebhookCallback struct {
	endpoint string
	headers  map[string]string
	secret   string
	client   *http.Client
}

// NewWebhookCallback creates a generic webhook adapter.
// If secret is non-empty, each request body is signed with HMAC-SHA256
// and the signature is sent in the X-Signature-256 header.
func NewWebhookCallback(endpoint, secret string, headers map[string]string) *WebhookCallback {
	return &WebhookCallback{
		endpoint: endpoint,
		headers:  headers,
		secret:   secret,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// Name returns "webhook".
func (w *WebhookCallback) Name() string { return "webhook" }

// Send marshals the payload as JSON and POSTs it to the configured endpoint.
func (w *WebhookCallback) Send(ctx context.Context, payload *callbacks.CallbackPayload) error {
	if ctx == nil {
		ctx = context.Background()
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("webhook: marshal failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: create request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	// HMAC signing if a secret is configured.
	if w.secret != "" {
		mac := hmac.New(sha256.New, []byte(w.secret))
		mac.Write(body)
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Signature-256", "sha256="+sig)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: send failed: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// Health checks connectivity to the webhook endpoint.
func (w *WebhookCallback) Health() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.endpoint, nil)
	if err != nil {
		return fmt.Errorf("webhook: health request failed: %w", err)
	}
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: health check failed: %w", err)
	}
	resp.Body.Close()

	// For webhooks, a non-error response (even 404) indicates connectivity.
	// Only network errors are treated as health failures.
	return nil
}
