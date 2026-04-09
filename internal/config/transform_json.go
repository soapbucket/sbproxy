// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"

	"github.com/soapbucket/sbproxy/internal/transformer"
)

func init() {
	transformLoaderFns[TransformJSON] = NewJSONTransform
}

// JSONTransformConfig holds configuration for json transformer.
type JSONTransformConfig struct {
	JSONTransform
}

// NewJSONTransform creates and initializes a new JSONTransform.
func NewJSONTransform(data []byte) (TransformConfig, error) {
	// First unmarshal into a map to handle set_fields
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	// Handle set_fields by converting to rules
	var setFields map[string]interface{}
	if jsonTransform, ok := raw["json_transform"].(map[string]interface{}); ok {
		if sf, ok := jsonTransform["set_fields"].(map[string]interface{}); ok {
			setFields = sf
			// Remove set_fields from json_transform
			delete(jsonTransform, "set_fields")
			// Re-marshal without set_fields
			var err2 error
			data, err2 = json.Marshal(raw)
			if err2 != nil {
				return nil, err2
			}
		}
	}

	cfg := &JSONTransformConfig{}
	err := json.Unmarshal(data, cfg)
	if err != nil {
		return nil, err
	}

	rules := make([]transformer.JSONRule, 0)
	// Add rules from set_fields
	for key, value := range setFields {
		if key != "" { // Skip empty keys
			rules = append(rules, transformer.JSONRule{
				Path:  key,
				Value: value,
			})
		}
	}
	// Add existing rules
	for _, rule := range cfg.Rules {
		if rule.Path != "" { // Skip empty paths
			rules = append(rules, transformer.JSONRule{
				Path:  rule.Path,
				Value: rule.Value,
			})
		}
	}

	// apply default content types if not set
	if cfg.ContentTypes == nil {
		cfg.ContentTypes = JSONContentTypes
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

	cfg.tr = transformer.OptimizeJSON(options)

	return cfg, nil
}
