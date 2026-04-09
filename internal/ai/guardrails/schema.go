// Package guardrails provides content safety filters and input/output validation for AI requests.
package guardrails

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	json "github.com/goccy/go-json"
	"github.com/xeipuuv/gojsonschema"
)

func init() {
	Register("json_schema", NewSchemaGuard)
}

// SchemaConfig configures JSON schema validation.
type SchemaConfig struct {
	Schema          json.RawMessage `json:"schema"`
	ExtractFromCode bool            `json:"extract_from_code,omitempty"` // Extract JSON from markdown code blocks
	RecoverPartial  bool            `json:"recover_partial,omitempty"`  // Try to fix truncated JSON
}

type schemaGuard struct {
	schema          *gojsonschema.Schema
	extractFromCode bool
	recoverPartial  bool
}

// NewSchemaGuard creates a JSON schema validation guardrail.
func NewSchemaGuard(config json.RawMessage) (Guardrail, error) {
	cfg := &SchemaConfig{}
	if len(config) > 0 {
		if err := json.Unmarshal(config, cfg); err != nil {
			return nil, err
		}
	}

	if len(cfg.Schema) == 0 {
		return nil, fmt.Errorf("json_schema guardrail requires a schema")
	}

	loader := gojsonschema.NewBytesLoader(cfg.Schema)
	schema, err := gojsonschema.NewSchema(loader)
	if err != nil {
		return nil, fmt.Errorf("invalid JSON schema: %w", err)
	}

	return &schemaGuard{
		schema:          schema,
		extractFromCode: cfg.ExtractFromCode,
		recoverPartial:  cfg.RecoverPartial,
	}, nil
}

// Name performs the name operation on the schemaGuard.
func (g *schemaGuard) Name() string  { return "json_schema" }
// Phase performs the phase operation on the schemaGuard.
func (g *schemaGuard) Phase() Phase  { return PhaseOutput }

// extractJSONFromMarkdown extracts JSON content from markdown code blocks.
func extractJSONFromMarkdown(text string) string {
	// Try ```json ... ``` first
	re := regexp.MustCompile("(?s)```(?:json)?\\s*\\n?(.*?)```")
	matches := re.FindStringSubmatch(text)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return text
}

// recoverTruncatedJSON attempts to fix JSON that was truncated during streaming.
func recoverTruncatedJSON(text string) string {
	text = strings.TrimSpace(text)
	if len(text) == 0 {
		return text
	}

	// Count open/close braces and brackets
	openBraces := strings.Count(text, "{") - strings.Count(text, "}")
	openBrackets := strings.Count(text, "[") - strings.Count(text, "]")

	// If already balanced, return as-is
	if openBraces == 0 && openBrackets == 0 {
		return text
	}

	// Remove any trailing incomplete key-value pair (e.g., trailing comma + incomplete key)
	// Trim trailing comma
	text = strings.TrimRight(text, " \t\n\r")
	if strings.HasSuffix(text, ",") {
		text = text[:len(text)-1]
	}

	// Close open brackets and braces
	for i := 0; i < openBrackets; i++ {
		text += "]"
	}
	for i := 0; i < openBraces; i++ {
		text += "}"
	}

	return text
}

// Check performs the check operation on the schemaGuard.
func (g *schemaGuard) Check(_ context.Context, content *Content) (*Result, error) {
	text := content.ExtractText()
	if text == "" {
		return &Result{Pass: true, Action: ActionAllow}, nil
	}

	// Extract JSON from markdown code blocks if enabled
	if g.extractFromCode {
		text = extractJSONFromMarkdown(text)
	}

	// Try to parse as JSON
	var doc interface{}
	if err := json.Unmarshal([]byte(text), &doc); err != nil {
		// Try partial recovery if enabled
		if g.recoverPartial {
			recovered := recoverTruncatedJSON(text)
			if err2 := json.Unmarshal([]byte(recovered), &doc); err2 != nil {
				return &Result{
					Pass:   false,
					Action: ActionBlock,
					Reason: "Output is not valid JSON",
					Details: map[string]any{
						"error":          err.Error(),
						"recovery_error": err2.Error(),
					},
				}, nil
			}
		} else {
			return &Result{
				Pass:   false,
				Action: ActionBlock,
				Reason: "Output is not valid JSON",
				Details: map[string]any{
					"error": err.Error(),
				},
			}, nil
		}
	}

	docLoader := gojsonschema.NewGoLoader(doc)
	result, err := g.schema.Validate(docLoader)
	if err != nil {
		return nil, fmt.Errorf("schema validation error: %w", err)
	}

	if !result.Valid() {
		var errors []string
		for _, e := range result.Errors() {
			errors = append(errors, e.String())
		}
		return &Result{
			Pass:   false,
			Action: ActionBlock,
			Reason: "Output does not match schema: " + strings.Join(errors, "; "),
			Details: map[string]any{
				"errors": errors,
			},
		}, nil
	}

	return &Result{Pass: true, Action: ActionAllow}, nil
}

// Transform performs the transform operation on the schemaGuard.
func (g *schemaGuard) Transform(_ context.Context, content *Content) (*Content, error) {
	return content, nil
}
