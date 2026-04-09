// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// newHTTPClientWithTimeout creates an http.Client with the given timeout.
func newHTTPClientWithTimeout(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
	}
}

// extractFieldFromString extracts a field from a JSON string value.
// If fieldName is empty, the raw value is returned as-is.
// If fieldName is set, the value is parsed as JSON and the field is extracted.
func extractFieldFromString(raw string, fieldName string, providerName string) (string, error) {
	if fieldName == "" {
		return raw, nil
	}

	var data map[string]any
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return "", fmt.Errorf("vault %s: secret value is not valid JSON (needed for field selector %q): %w", providerName, fieldName, err)
	}

	val, ok := data[fieldName]
	if !ok {
		return "", fmt.Errorf("vault %s: field %q not found in secret JSON", providerName, fieldName)
	}

	str, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("vault %s: field %q is not a string", providerName, fieldName)
	}
	return str, nil
}
