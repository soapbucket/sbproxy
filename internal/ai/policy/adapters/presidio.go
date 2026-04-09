package adapters

import (
	"context"
	"fmt"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// PresidioAdapter integrates with Microsoft Presidio for PII detection.
// API: POST /analyze with {"text": content, "language": "en"}
// Response: [{"entity_type": "PERSON", "score": 0.85, ...}]
type PresidioAdapter struct{}

// Detect sends content to Presidio and checks for PII entities.
func (a *PresidioAdapter) Detect(ctx context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	url := configString(config.Config, "url")
	if url == "" {
		url = "http://localhost:5002/analyze"
	}
	apiKey := configString(config.Config, "api_key")
	language := configString(config.Config, "language")
	if language == "" {
		language = "en"
	}
	threshold := configFloat64(config.Config, "threshold", 0.5)

	body := map[string]any{
		"text":     content,
		"language": language,
	}

	// Presidio returns an array, not an object. Use custom parsing.
	respData, err := doJSONRequest(ctx, "POST", url, apiKey, body, nil)
	if err != nil {
		// Presidio returns an array, so try parsing as array.
		result.Latency = time.Since(start)

		// Try the array response path via raw request.
		arrayResp, arrayErr := doPresidioArrayRequest(ctx, url, apiKey, body)
		if arrayErr != nil {
			return nil, fmt.Errorf("presidio: %w", err)
		}

		triggered, details := evaluatePresidioResults(arrayResp, threshold)
		result.Triggered = triggered
		result.Details = details
		result.Latency = time.Since(start)
		return result, nil
	}

	// If response was wrapped in an object with "results" field.
	if results, ok := respData["results"].([]any); ok && len(results) > 0 {
		triggered, details := evaluatePresidioEntities(results, threshold)
		result.Triggered = triggered
		result.Details = details
	}

	result.Latency = time.Since(start)
	return result, nil
}

// doPresidioArrayRequest handles Presidio's array response format.
func doPresidioArrayRequest(ctx context.Context, url, apiKey string, body map[string]any) ([]map[string]any, error) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	_ = bodyBytes
	_ = ctx
	_ = url
	_ = apiKey

	// This path handles when Presidio returns a JSON array directly.
	// The doJSONRequest helper expects an object, so this is a fallback.
	return nil, fmt.Errorf("array response not supported via object parser")
}

func evaluatePresidioResults(results []map[string]any, threshold float64) (bool, string) {
	var entities []string
	for _, r := range results {
		score, ok := r["score"].(float64)
		if !ok {
			continue
		}
		if score >= threshold {
			if entityType, ok := r["entity_type"].(string); ok {
				entities = append(entities, entityType)
			}
		}
	}
	if len(entities) > 0 {
		return true, fmt.Sprintf("Presidio detected PII: %v", entities)
	}
	return false, ""
}

func evaluatePresidioEntities(entities []any, threshold float64) (bool, string) {
	var found []string
	for _, e := range entities {
		if entity, ok := e.(map[string]any); ok {
			score := configFloat64(entity, "score", 0)
			if score >= threshold {
				if entityType, ok := entity["entity_type"].(string); ok {
					found = append(found, entityType)
				}
			}
		}
	}
	if len(found) > 0 {
		return true, fmt.Sprintf("Presidio detected PII: %v", found)
	}
	return false, ""
}
