package builtin

import (
	"context"
	"fmt"
	"strings"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// MetadataDetector checks that required metadata keys are present in content.
// Content should be a JSON object with metadata key-value pairs.
// Config fields:
//   - "required_keys" ([]string) - list of required metadata keys
//   - "required_values" (map[string]any) - map of required key-value pairs
type MetadataDetector struct{}

// Detect checks content (JSON metadata) for required keys and values.
func (d *MetadataDetector) Detect(_ context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	requiredKeys, _ := toStringSlice(config.Config["required_keys"])
	requiredValues, _ := toMapStringAny(config.Config["required_values"])

	var metadata map[string]any
	if err := json.Unmarshal([]byte(content), &metadata); err != nil {
		// If content is not JSON, check it as raw text (all keys missing).
		if len(requiredKeys) > 0 || len(requiredValues) > 0 {
			result.Triggered = true
			result.Details = "content is not valid JSON metadata"
		}
		result.Latency = time.Since(start)
		return result, nil
	}

	var missing []string

	for _, key := range requiredKeys {
		if _, exists := metadata[key]; !exists {
			missing = append(missing, key)
		}
	}

	for key, expectedVal := range requiredValues {
		actualVal, exists := metadata[key]
		if !exists {
			missing = append(missing, fmt.Sprintf("%s (missing)", key))
			continue
		}
		if fmt.Sprintf("%v", actualVal) != fmt.Sprintf("%v", expectedVal) {
			missing = append(missing, fmt.Sprintf("%s (expected %v, got %v)", key, expectedVal, actualVal))
		}
	}

	if len(missing) > 0 {
		result.Triggered = true
		result.Details = fmt.Sprintf("metadata issues: %s", strings.Join(missing, "; "))
	}

	result.Latency = time.Since(start)
	return result, nil
}
