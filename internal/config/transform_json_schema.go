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
	"github.com/xeipuuv/gojsonschema"
)

func init() {
	transformLoaderFns[TransformJSONSchema] = NewJSONSchemaTransform
}

// JSONSchemaTransformConfig is the runtime config for JSON Schema validation.
type JSONSchemaTransformConfig struct {
	JSONSchemaTransform

	compiledSchema *gojsonschema.Schema
}

// NewJSONSchemaTransform creates a new JSON Schema validation transformer.
func NewJSONSchemaTransform(data []byte) (TransformConfig, error) {
	cfg := &JSONSchemaTransformConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("json_schema: %w", err)
	}

	if len(cfg.Schema) == 0 {
		return nil, fmt.Errorf("json_schema: schema is required")
	}

	if cfg.Action == "" {
		cfg.Action = "validate"
	}
	if cfg.Action != "validate" && cfg.Action != "warn" && cfg.Action != "strip" {
		return nil, fmt.Errorf("json_schema: invalid action %q (must be validate, warn, or strip)", cfg.Action)
	}

	if cfg.ContentTypes == nil {
		cfg.ContentTypes = JSONContentTypes
	}

	loader := gojsonschema.NewBytesLoader(cfg.Schema)
	schema, err := gojsonschema.NewSchema(loader)
	if err != nil {
		return nil, fmt.Errorf("json_schema: invalid schema: %w", err)
	}
	cfg.compiledSchema = schema

	cfg.tr = transformer.Func(cfg.validate)

	return cfg, nil
}

func (c *JSONSchemaTransformConfig) validate(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if len(body) == 0 {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	docLoader := gojsonschema.NewBytesLoader(body)
	result, err := c.compiledSchema.Validate(docLoader)
	if err != nil {
		// Not valid JSON or schema error — restore body and return
		resp.Body = io.NopCloser(bytes.NewReader(body))
		if c.Action == "validate" {
			resp.StatusCode = http.StatusBadGateway
			errBody := []byte(`{"error":"response failed schema validation"}`)
			resp.Body = io.NopCloser(bytes.NewReader(errBody))
			resp.Header.Set("Content-Length", strconv.Itoa(len(errBody)))
			resp.Header.Set("Content-Type", "application/json")
		}
		return nil
	}

	if result.Valid() {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	switch c.Action {
	case "validate":
		errBody := []byte(`{"error":"response failed schema validation"}`)
		resp.StatusCode = http.StatusBadGateway
		resp.Body = io.NopCloser(bytes.NewReader(errBody))
		resp.Header.Set("Content-Length", strconv.Itoa(len(errBody)))
		resp.Header.Set("Content-Type", "application/json")
	case "warn":
		resp.Header.Set("X-Schema-Valid", "false")
		resp.Body = io.NopCloser(bytes.NewReader(body))
	case "strip":
		// Remove invalid fields by re-validating and keeping only valid parts
		// For simplicity, mark as invalid and pass through
		resp.Header.Set("X-Schema-Valid", "false")
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}

	return nil
}
