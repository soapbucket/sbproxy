package builtin

import (
	"context"
	"fmt"
	"strings"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// SchemaDetector validates JSON content against a schema defined in config.
// Config fields:
//   - "schema" (map[string]any) - JSON schema definition with "type", "required", "properties"
//   - "strict" (bool) - if true, reject unknown properties (default: false)
type SchemaDetector struct{}

// Detect validates content against the configured JSON schema.
func (d *SchemaDetector) Detect(_ context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	schema, ok := toMapStringAny(config.Config["schema"])
	if !ok {
		result.Latency = time.Since(start)
		return result, nil
	}

	strict, _ := toBool(config.Config["strict"])

	var parsed any
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		result.Triggered = true
		result.Details = fmt.Sprintf("invalid JSON: %s", err.Error())
		result.Latency = time.Since(start)
		return result, nil
	}

	violations := validateAgainstSchema(parsed, schema, strict, "")
	if len(violations) > 0 {
		result.Triggered = true
		result.Details = fmt.Sprintf("schema violations: %s", strings.Join(violations, "; "))
	}

	result.Latency = time.Since(start)
	return result, nil
}

// validateAgainstSchema performs basic JSON schema validation.
func validateAgainstSchema(data any, schema map[string]any, strict bool, path string) []string {
	var violations []string

	// Check type.
	if expectedType, ok := toString(schema["type"]); ok {
		actual := jsonType(data)
		if actual != expectedType {
			violations = append(violations, fmt.Sprintf("%s: expected type %q, got %q", pathStr(path), expectedType, actual))
			return violations
		}
	}

	// For object types, check required fields and properties.
	if obj, ok := data.(map[string]any); ok {
		// Check required fields.
		if required, ok := toStringSlice(schema["required"]); ok {
			for _, field := range required {
				if _, exists := obj[field]; !exists {
					violations = append(violations, fmt.Sprintf("%s: missing required field %q", pathStr(path), field))
				}
			}
		}

		// Validate properties.
		if properties, ok := toMapStringAny(schema["properties"]); ok {
			for key, propSchema := range properties {
				if val, exists := obj[key]; exists {
					if ps, ok := propSchema.(map[string]any); ok {
						subPath := key
						if path != "" {
							subPath = path + "." + key
						}
						violations = append(violations, validateAgainstSchema(val, ps, strict, subPath)...)
					}
				}
			}

			// Strict mode: reject unknown properties.
			if strict {
				for key := range obj {
					if _, defined := properties[key]; !defined {
						violations = append(violations, fmt.Sprintf("%s: unknown property %q", pathStr(path), key))
					}
				}
			}
		}
	}

	// For array types, validate items.
	if arr, ok := data.([]any); ok {
		if items, ok := toMapStringAny(schema["items"]); ok {
			for i, item := range arr {
				subPath := fmt.Sprintf("%s[%d]", pathStr(path), i)
				violations = append(violations, validateAgainstSchema(item, items, strict, subPath)...)
			}
		}

		// Check minItems/maxItems.
		if minItems, ok := toInt(schema["minItems"]); ok && len(arr) < minItems {
			violations = append(violations, fmt.Sprintf("%s: array length %d < minItems %d", pathStr(path), len(arr), minItems))
		}
		if maxItems, ok := toInt(schema["maxItems"]); ok && len(arr) > maxItems {
			violations = append(violations, fmt.Sprintf("%s: array length %d > maxItems %d", pathStr(path), len(arr), maxItems))
		}
	}

	return violations
}

// jsonType returns the JSON type name for a Go value.
func jsonType(v any) string {
	switch v.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "boolean"
	case nil:
		return "null"
	default:
		return "unknown"
	}
}

// pathStr returns a display path string.
func pathStr(path string) string {
	if path == "" {
		return "$"
	}
	return "$." + path
}
