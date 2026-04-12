// Package modifier provides request and response modification capabilities for header, body, and URL transformations.
package modifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/tidwall/gjson"
)

// AISchemaValidationConfig configures request-side AI API schema validation.
// Validates inbound requests match the expected AI provider format before forwarding.
type AISchemaValidationConfig struct {
	Provider       string   `json:"provider"`                  // "openai", "anthropic", "generic"
	Action         string   `json:"action,omitempty"`          // "reject" (default), "warn"
	StatusCode     int      `json:"status_code,omitempty"`     // HTTP status for reject (default: 400)
	RequiredFields []string `json:"required_fields,omitempty"` // Additional required fields
	ContentTypes   []string `json:"content_types,omitempty"`   // Content types to validate
}

func applyAISchemaValidation(req *http.Request, cfg *AISchemaValidationConfig) error {
	if req.Body == nil || req.ContentLength == 0 {
		return nil
	}

	// Check content type
	ct := parseMediaType(req.Header.Get("Content-Type"))
	contentTypes := cfg.ContentTypes
	if contentTypes == nil {
		contentTypes = []string{"application/json"}
	}
	matched := false
	for _, allowed := range contentTypes {
		if allowed == ct {
			matched = true
			break
		}
	}
	if !matched {
		return nil
	}

	// Read body
	body, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		req.Body = io.NopCloser(bytes.NewReader(nil))
		return fmt.Errorf("ai_schema_validation: failed to read body: %w", err)
	}

	if len(body) == 0 {
		req.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	// Validate
	errors := validateAIRequest(body, cfg.Provider, cfg.RequiredFields)

	// Restore body
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))

	if len(errors) == 0 {
		return nil
	}

	action := cfg.Action
	if action == "" {
		action = "reject"
	}

	switch action {
	case "reject":
		statusCode := cfg.StatusCode
		if statusCode == 0 {
			statusCode = http.StatusBadRequest
		}
		errBody, _ := json.Marshal(map[string]interface{}{
			"error":             "AI API request schema validation failed",
			"validation_errors": errors,
		})
		// Replace the body with the error and set a marker header
		// The caller (middleware/handler) should check this header
		req.Body = io.NopCloser(bytes.NewReader(errBody))
		req.ContentLength = int64(len(errBody))
		req.Header.Set("Content-Length", strconv.Itoa(len(errBody)))
		req.Header.Set("X-AI-Schema-Reject", strconv.Itoa(statusCode))
		req.Header.Set("X-AI-Schema-Errors", strings.Join(errors, "; "))
	case "warn":
		req.Header.Set("X-AI-Schema-Valid", "false")
		req.Header.Set("X-AI-Schema-Errors", strings.Join(errors, "; "))
	}

	return nil
}

func validateAIRequest(body []byte, provider string, requiredFields []string) []string {
	switch provider {
	case "openai":
		return validateOpenAIRequest(body, requiredFields)
	case "anthropic":
		return validateAnthropicRequest(body, requiredFields)
	default:
		return validateGenericAIRequest(body, requiredFields)
	}
}

func validateOpenAIRequest(body []byte, extra []string) []string {
	var errors []string

	if !gjson.GetBytes(body, "model").Exists() {
		errors = append(errors, "missing 'model' field")
	}
	if !gjson.GetBytes(body, "messages").Exists() {
		errors = append(errors, "missing 'messages' array")
	} else if !gjson.GetBytes(body, "messages").IsArray() {
		errors = append(errors, "'messages' must be an array")
	}

	for _, field := range extra {
		if !gjson.GetBytes(body, field).Exists() {
			errors = append(errors, fmt.Sprintf("missing required field '%s'", field))
		}
	}

	return errors
}

func validateAnthropicRequest(body []byte, extra []string) []string {
	var errors []string

	if !gjson.GetBytes(body, "model").Exists() {
		errors = append(errors, "missing 'model' field")
	}
	if !gjson.GetBytes(body, "messages").Exists() {
		errors = append(errors, "missing 'messages' array")
	} else if !gjson.GetBytes(body, "messages").IsArray() {
		errors = append(errors, "'messages' must be an array")
	}
	if !gjson.GetBytes(body, "max_tokens").Exists() {
		errors = append(errors, "missing 'max_tokens' field")
	}

	for _, field := range extra {
		if !gjson.GetBytes(body, field).Exists() {
			errors = append(errors, fmt.Sprintf("missing required field '%s'", field))
		}
	}

	return errors
}

func validateGenericAIRequest(body []byte, extra []string) []string {
	var errors []string

	// Generic: must at least be valid JSON with some structure
	if !gjson.ValidBytes(body) {
		errors = append(errors, "invalid JSON")
		return errors
	}

	for _, field := range extra {
		if !gjson.GetBytes(body, field).Exists() {
			errors = append(errors, fmt.Sprintf("missing required field '%s'", field))
		}
	}

	return errors
}
