// Package adapters provides external guardrail service adapters for the AI gateway.
// Each adapter implements the policy.GuardrailDetector interface and communicates
// with a specific external moderation or safety service.
package adapters

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

const maxResponseBody = 1 << 20 // 1 MB

// baseResult creates a base GuardrailResult from a config.
func baseResult(config *policy.GuardrailConfig) *policy.GuardrailResult {
	return &policy.GuardrailResult{
		GuardrailID: config.ID,
		Name:        config.Name,
		Action:      config.Action,
		Async:       config.Async,
	}
}

// configString reads a string from the guardrail config map.
func configString(config map[string]any, key string) string {
	v, _ := config[key].(string)
	return v
}

// configFloat64 reads a float64 from the guardrail config map with a default.
func configFloat64(config map[string]any, key string, defaultVal float64) float64 {
	switch v := config[key].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	default:
		return defaultVal
	}
}

// doJSONRequest sends a JSON request and returns the parsed response.
func doJSONRequest(ctx context.Context, method, url, apiKey string, body any, headers map[string]string) (map[string]any, error) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return result, nil
}
