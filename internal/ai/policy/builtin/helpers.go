// Package builtin provides 22 built-in guardrail detectors for the AI gateway.
package builtin

import (
	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// toStringSlice extracts a string slice from an interface value.
func toStringSlice(v any) ([]string, bool) {
	if v == nil {
		return nil, false
	}
	switch s := v.(type) {
	case []string:
		return s, true
	case []any:
		result := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result, true
	default:
		return nil, false
	}
}

// toFloat64 extracts a float64 from an interface value.
func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}

// toInt extracts an int from an interface value.
func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case float64:
		return int(n), true
	case int64:
		return int(n), true
	default:
		return 0, false
	}
}

// toString extracts a string from an interface value.
func toString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// toBool extracts a bool from an interface value.
func toBool(v any) (bool, bool) {
	b, ok := v.(bool)
	return b, ok
}

// toMapStringAny extracts a map[string]any from an interface value.
func toMapStringAny(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

// baseResult creates a base GuardrailResult from a config.
func baseResult(config *policy.GuardrailConfig) *policy.GuardrailResult {
	return &policy.GuardrailResult{
		GuardrailID: config.ID,
		Name:        config.Name,
		Action:      config.Action,
	}
}
