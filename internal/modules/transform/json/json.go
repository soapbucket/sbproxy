// Package json registers the json transform.
package json

import (
	stdjson "encoding/json"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/transformer"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterTransform("json", New)
}

// JSONRule is a single JSON transformation rule.
type JSONRule struct {
	Path  string `json:"path"`
	Value any    `json:"value"`
}

// Config holds configuration for the json transform.
type Config struct {
	Type                string     `json:"type"`
	ContentTypes        []string   `json:"content_types,omitempty"`
	RemoveEmptyObjects  bool       `json:"remove_empty_objects"`
	RemoveEmptyArrays   bool       `json:"remove_empty_arrays"`
	RemoveFalseBooleans bool       `json:"remove_false_booleans"`
	RemoveEmptyStrings  bool       `json:"remove_empty_strings"`
	RemoveZeroNumbers   bool       `json:"remove_zero_numbers"`
	PrettyPrint         bool       `json:"pretty_print"`
	Rules               []JSONRule `json:"rules"`
	JSONTransform       *struct {
		SetFields map[string]interface{} `json:"set_fields,omitempty"`
	} `json:"json_transform,omitempty"`
}

// jsonTransform implements plugin.TransformHandler.
type jsonTransform struct {
	tr transformer.Transformer
}

// New creates a new json transform.
func New(data stdjson.RawMessage) (plugin.TransformHandler, error) {
	// First unmarshal into a map to handle set_fields
	var raw map[string]interface{}
	if err := stdjson.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	// Handle set_fields by converting to rules
	var setFields map[string]interface{}
	if jsonTransform, ok := raw["json_transform"].(map[string]interface{}); ok {
		if sf, ok := jsonTransform["set_fields"].(map[string]interface{}); ok {
			setFields = sf
			delete(jsonTransform, "set_fields")
			var err2 error
			data, err2 = stdjson.Marshal(raw)
			if err2 != nil {
				return nil, err2
			}
		}
	}

	var cfg Config
	if err := stdjson.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	rules := make([]transformer.JSONRule, 0)
	for key, value := range setFields {
		if key != "" {
			rules = append(rules, transformer.JSONRule{
				Path:  key,
				Value: value,
			})
		}
	}
	for _, rule := range cfg.Rules {
		if rule.Path != "" {
			rules = append(rules, transformer.JSONRule{
				Path:  rule.Path,
				Value: rule.Value,
			})
		}
	}

	options := transformer.JSONOptions{
		RemoveEmptyObjects:  cfg.RemoveEmptyObjects,
		RemoveEmptyArrays:   cfg.RemoveEmptyArrays,
		RemoveFalseBooleans: cfg.RemoveFalseBooleans,
		RemoveEmptyStrings:  cfg.RemoveEmptyStrings,
		RemoveZeroNumbers:   cfg.RemoveZeroNumbers,
		PrettyPrint:         cfg.PrettyPrint,
		Rules:               rules,
	}

	return &jsonTransform{
		tr: transformer.OptimizeJSON(options),
	}, nil
}

func (j *jsonTransform) Type() string                    { return "json" }
func (j *jsonTransform) Apply(resp *http.Response) error { return j.tr.Modify(resp) }
