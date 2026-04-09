// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/soapbucket/sbproxy/internal/transformer"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func init() {
	transformLoaderFns[TransformAISchema] = NewAISchemaTransform
}

// AISchemaTransformConfig is the runtime config for AI API schema validation.
type AISchemaTransformConfig struct {
	AISchemaTransform
}

// NewAISchemaTransform creates a new AI schema validation transformer.
func NewAISchemaTransform(data []byte) (TransformConfig, error) {
	cfg := &AISchemaTransformConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("ai_schema: %w", err)
	}

	if cfg.Provider == "" {
		cfg.Provider = "generic"
	}

	if cfg.Action == "" {
		cfg.Action = "validate"
	}
	if cfg.Action != "validate" && cfg.Action != "warn" && cfg.Action != "fix" {
		return nil, fmt.Errorf("ai_schema: invalid action %q (must be validate, warn, or fix)", cfg.Action)
	}

	if cfg.ContentTypes == nil {
		cfg.ContentTypes = JSONContentTypes
	}

	cfg.tr = transformer.Func(cfg.validate)

	return cfg, nil
}

func (c *AISchemaTransformConfig) validate(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if len(body) == 0 {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	errors := c.validateSchema(body)

	if len(errors) == 0 {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	switch c.Action {
	case "validate":
		errBody, _ := json.Marshal(map[string]interface{}{
			"error":             "AI API response schema validation failed",
			"validation_errors": errors,
		})
		resp.StatusCode = http.StatusBadGateway
		resp.Body = io.NopCloser(bytes.NewReader(errBody))
		resp.Header.Set("Content-Length", strconv.Itoa(len(errBody)))
		resp.Header.Set("Content-Type", "application/json")
	case "warn":
		resp.Header.Set("X-AI-Schema-Valid", "false")
		resp.Body = io.NopCloser(bytes.NewReader(body))
	case "fix":
		fixed := c.fixSchema(body)
		resp.Body = io.NopCloser(bytes.NewReader(fixed))
		resp.Header.Set("Content-Length", strconv.Itoa(len(fixed)))
		resp.Header.Set("X-AI-Schema-Fixed", "true")
	}

	return nil
}

func (c *AISchemaTransformConfig) validateSchema(body []byte) []string {
	switch c.Provider {
	case "openai":
		return validateOpenAIResponse(body)
	case "anthropic":
		return validateAnthropicResponse(body)
	default:
		return validateGenericAIResponse(body)
	}
}

func validateOpenAIResponse(body []byte) []string {
	var errors []string

	if !gjson.GetBytes(body, "id").Exists() {
		errors = append(errors, "missing 'id' field")
	}
	if !gjson.GetBytes(body, "object").Exists() {
		errors = append(errors, "missing 'object' field")
	}
	if !gjson.GetBytes(body, "choices").Exists() {
		errors = append(errors, "missing 'choices' array")
	}
	if !gjson.GetBytes(body, "model").Exists() {
		errors = append(errors, "missing 'model' field")
	}

	return errors
}

func validateAnthropicResponse(body []byte) []string {
	var errors []string

	if !gjson.GetBytes(body, "id").Exists() {
		errors = append(errors, "missing 'id' field")
	}
	if !gjson.GetBytes(body, "type").Exists() {
		errors = append(errors, "missing 'type' field")
	}
	if !gjson.GetBytes(body, "content").Exists() {
		errors = append(errors, "missing 'content' array")
	}
	if !gjson.GetBytes(body, "role").Exists() {
		errors = append(errors, "missing 'role' field")
	}
	if !gjson.GetBytes(body, "model").Exists() {
		errors = append(errors, "missing 'model' field")
	}

	return errors
}

func validateGenericAIResponse(body []byte) []string {
	var errors []string

	// Generic: must have at least choices or content
	hasChoices := gjson.GetBytes(body, "choices").Exists()
	hasContent := gjson.GetBytes(body, "content").Exists()

	if !hasChoices && !hasContent {
		errors = append(errors, "missing 'choices' or 'content' field")
	}

	return errors
}

func (c *AISchemaTransformConfig) fixSchema(body []byte) []byte {
	result := body
	var err error

	switch c.Provider {
	case "openai":
		if !gjson.GetBytes(result, "object").Exists() {
			result, err = sjson.SetBytes(result, "object", "chat.completion")
			if err != nil {
				return body
			}
		}
		if !gjson.GetBytes(result, "choices").Exists() {
			result, err = sjson.SetRawBytes(result, "choices", []byte("[]"))
			if err != nil {
				return body
			}
		}
	case "anthropic":
		if !gjson.GetBytes(result, "type").Exists() {
			result, err = sjson.SetBytes(result, "type", "message")
			if err != nil {
				return body
			}
		}
		if !gjson.GetBytes(result, "role").Exists() {
			result, err = sjson.SetBytes(result, "role", "assistant")
			if err != nil {
				return body
			}
		}
		if !gjson.GetBytes(result, "content").Exists() {
			result, err = sjson.SetRawBytes(result, "content", []byte("[]"))
			if err != nil {
				return body
			}
		}
	}

	return result
}
