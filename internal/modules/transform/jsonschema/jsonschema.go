// Package jsonschema registers the json_schema transform.
package jsonschema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/soapbucket/sbproxy/pkg/plugin"
	"github.com/xeipuuv/gojsonschema"
)

func init() {
	plugin.RegisterTransform("json_schema", New)
}

// Config holds configuration for the json_schema transform.
type Config struct {
	Type         string          `json:"type"`
	Schema       json.RawMessage `json:"schema"`
	Action       string          `json:"action,omitempty"`
	ContentTypes []string        `json:"content_types,omitempty"`
}

// jsonSchemaTransform implements plugin.TransformHandler.
type jsonSchemaTransform struct {
	compiledSchema *gojsonschema.Schema
	action         string
}

// New creates a new json_schema transform.
func New(data json.RawMessage) (plugin.TransformHandler, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
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

	loader := gojsonschema.NewBytesLoader(cfg.Schema)
	schema, err := gojsonschema.NewSchema(loader)
	if err != nil {
		return nil, fmt.Errorf("json_schema: invalid schema: %w", err)
	}

	return &jsonSchemaTransform{
		compiledSchema: schema,
		action:         cfg.Action,
	}, nil
}

func (c *jsonSchemaTransform) Type() string { return "json_schema" }
func (c *jsonSchemaTransform) Apply(resp *http.Response) error {
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
		resp.Body = io.NopCloser(bytes.NewReader(body))
		if c.action == "validate" {
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

	switch c.action {
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
		resp.Header.Set("X-Schema-Valid", "false")
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}

	return nil
}
