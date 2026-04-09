package identity

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	json "github.com/goccy/go-json"
)

// WebhookConnector resolves permissions via a webhook endpoint with retry and circuit breaker.
type WebhookConnector struct {
	url        string
	httpClient *http.Client
	timeout    time.Duration
	retryCount int

	// Simple circuit breaker state.
	failures  atomic.Int64
	lastFail  atomic.Int64 // Unix timestamp of last failure
	threshold int64        // Max consecutive failures before circuit opens (default 5)
	cooldown  time.Duration
}

// NewWebhookConnector creates a webhook-based permission connector.
func NewWebhookConnector(url string, timeout time.Duration, retryCount int) *WebhookConnector {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	if retryCount < 1 {
		retryCount = 1
	}
	return &WebhookConnector{
		url: url,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		timeout:   timeout,
		retryCount: retryCount,
		threshold:  5,
		cooldown:   30 * time.Second,
	}
}

// webhookRequest is the JSON body sent to the webhook.
type webhookRequest struct {
	CredentialType string `json:"credential_type"`
	Credential     string `json:"credential"`
	Timestamp      string `json:"timestamp"`
}

// webhookResponse is the expected JSON response from the webhook.
type webhookResponse struct {
	Principal   string   `json:"principal"`
	Groups      []string `json:"groups"`
	Models      []string `json:"models"`
	Permissions []string `json:"permissions"`
}

// isCircuitOpen checks if the circuit breaker is in the open state.
func (w *WebhookConnector) isCircuitOpen() bool {
	failures := w.failures.Load()
	if failures < w.threshold {
		return false
	}
	lastFail := w.lastFail.Load()
	elapsed := time.Since(time.Unix(lastFail, 0))
	if elapsed > w.cooldown {
		// Cooldown expired, allow a probe request (half-open).
		return false
	}
	return true
}

// recordSuccess resets the circuit breaker.
func (w *WebhookConnector) recordSuccess() {
	w.failures.Store(0)
}

// recordFailure increments the failure counter and updates the last failure timestamp.
func (w *WebhookConnector) recordFailure() {
	w.failures.Add(1)
	w.lastFail.Store(time.Now().Unix())
}

// Resolve calls the webhook endpoint with retries on 5xx errors.
// The circuit breaker opens after consecutive failures and enters a cooldown period
// before allowing another probe request.
// Returns nil, nil when the endpoint returns 404 (credential not found).
func (w *WebhookConnector) Resolve(ctx context.Context, credentialType, credential string) (*CachedPermission, error) {
	if w.isCircuitOpen() {
		return nil, fmt.Errorf("identity: webhook circuit breaker open")
	}

	reqBody := webhookRequest{
		CredentialType: credentialType,
		Credential:     credential,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("identity: webhook marshal request: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < w.retryCount; attempt++ {
		perm, err := w.doRequest(ctx, bodyBytes)
		if err == nil {
			w.recordSuccess()
			return perm, nil
		}
		lastErr = err

		// Only retry on server errors, not client errors or context cancellation.
		if ctx.Err() != nil {
			break
		}
	}

	w.recordFailure()
	return nil, fmt.Errorf("identity: webhook failed after %d attempts: %w", w.retryCount, lastErr)
}

// doRequest performs a single webhook HTTP request.
func (w *WebhookConnector) doRequest(ctx context.Context, bodyBytes []byte) (*CachedPermission, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := w.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode >= 500 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("server error %d: %s", resp.StatusCode, string(body))
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var result webhookResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	now := time.Now()
	return &CachedPermission{
		Principal:   result.Principal,
		Groups:      result.Groups,
		Models:      result.Models,
		Permissions: result.Permissions,
		CachedAt:    now,
		ExpiresAt:   now.Add(5 * time.Minute),
	}, nil
}
