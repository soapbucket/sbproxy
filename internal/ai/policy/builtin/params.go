package builtin

import (
	"context"
	"fmt"
	"strings"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// ParamsDetector guards request parameters (temperature, max_tokens, etc.) against bounds.
// Content should be a JSON object with the request parameters.
// Config fields:
//   - "rules" (map[string]any) - parameter rules, each keyed by parameter name:
//     - "min" (float64) - minimum allowed value
//     - "max" (float64) - maximum allowed value
//     - "allowed" ([]any) - list of allowed values
type ParamsDetector struct{}

// Detect checks content (JSON parameters) against configured bounds.
func (d *ParamsDetector) Detect(_ context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	rules, _ := toMapStringAny(config.Config["rules"])
	if len(rules) == 0 {
		result.Latency = time.Since(start)
		return result, nil
	}

	var params map[string]any
	if err := json.Unmarshal([]byte(content), &params); err != nil {
		result.Triggered = true
		result.Details = "content is not valid JSON"
		result.Latency = time.Since(start)
		return result, nil
	}

	var violations []string

	for paramName, ruleVal := range rules {
		rule, ok := ruleVal.(map[string]any)
		if !ok {
			continue
		}

		actualVal, exists := params[paramName]
		if !exists {
			continue
		}

		actualNum, isNum := toFloat64(actualVal)

		if minVal, ok := toFloat64(rule["min"]); ok && isNum {
			if actualNum < minVal {
				violations = append(violations, fmt.Sprintf("%s=%.2f < min %.2f", paramName, actualNum, minVal))
			}
		}

		if maxVal, ok := toFloat64(rule["max"]); ok && isNum {
			if actualNum > maxVal {
				violations = append(violations, fmt.Sprintf("%s=%.2f > max %.2f", paramName, actualNum, maxVal))
			}
		}

		if allowedRaw, ok := rule["allowed"]; ok {
			if allowedSlice, ok := allowedRaw.([]any); ok {
				found := false
				for _, a := range allowedSlice {
					if fmt.Sprintf("%v", a) == fmt.Sprintf("%v", actualVal) {
						found = true
						break
					}
				}
				if !found {
					violations = append(violations, fmt.Sprintf("%s=%v not in allowed values", paramName, actualVal))
				}
			}
		}
	}

	if len(violations) > 0 {
		result.Triggered = true
		result.Details = fmt.Sprintf("parameter violations: %s", strings.Join(violations, "; "))
	}

	result.Latency = time.Since(start)
	return result, nil
}
