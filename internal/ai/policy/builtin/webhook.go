package builtin

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// WebhookDetector calls an external URL with the content and parses the response.
// Config fields:
//   - "url" (string) - the webhook URL to call
//   - "method" (string) - HTTP method (default: "POST")
//   - "headers" (map[string]any) - additional headers to send
//   - "timeout" (float64) - timeout in seconds (default: 5.0)
//   - "trigger_field" (string) - JSON field in response that indicates trigger (default: "triggered")
//   - "details_field" (string) - JSON field in response for details (default: "details")
type WebhookDetector struct {
	client *http.Client
}

// NewWebhookDetector creates a webhook detector with the given HTTP client.
// If client is nil, a default client with 10s timeout is used.
func NewWebhookDetector(client *http.Client) *WebhookDetector {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &WebhookDetector{client: client}
}

// Detect calls the configured webhook URL and parses the response.
func (d *WebhookDetector) Detect(ctx context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	webhookURL, ok := toString(config.Config["url"])
	if !ok || webhookURL == "" {
		result.Latency = time.Since(start)
		return result, nil
	}

	method, _ := toString(config.Config["method"])
	if method == "" {
		method = "POST"
	}

	timeoutSecs := 5.0
	if t, ok := toFloat64(config.Config["timeout"]); ok {
		timeoutSecs = t
	}

	triggerField, _ := toString(config.Config["trigger_field"])
	if triggerField == "" {
		triggerField = "triggered"
	}

	detailsField, _ := toString(config.Config["details_field"])
	if detailsField == "" {
		detailsField = "details"
	}

	// Build request body.
	body := map[string]any{
		"content":      content,
		"guardrail_id": config.ID,
		"name":         config.Name,
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal webhook body: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSecs*float64(time.Second)))
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, method, webhookURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create webhook request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add custom headers.
	if headers, ok := toMapStringAny(config.Config["headers"]); ok {
		for k, v := range headers {
			if sv, ok := v.(string); ok {
				req.Header.Set(k, sv)
			}
		}
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit.
	if err != nil {
		return nil, fmt.Errorf("failed to read webhook response: %w", err)
	}

	if resp.StatusCode >= 400 {
		result.Triggered = true
		result.Details = fmt.Sprintf("webhook returned status %d", resp.StatusCode)
		result.Latency = time.Since(start)
		return result, nil
	}

	var respData map[string]any
	if err := json.Unmarshal(respBody, &respData); err != nil {
		result.Latency = time.Since(start)
		return result, nil
	}

	if triggered, ok := respData[triggerField].(bool); ok && triggered {
		result.Triggered = true
		if details, ok := respData[detailsField].(string); ok {
			result.Details = details
		} else {
			result.Details = "webhook triggered"
		}
	}

	result.Latency = time.Since(start)
	return result, nil
}
