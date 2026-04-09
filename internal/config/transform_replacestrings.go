// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"

	"github.com/soapbucket/sbproxy/internal/transformer"
)

func init() {
	transformLoaderFns[TransformReplaceStrings] = NewReplaceStringsTransform
}

// ReplaceStringsTransformConfig holds configuration for replace strings transformer.
type ReplaceStringsTransformConfig struct {
	ReplaceStringTransform
}

// NewReplaceStringsTransform creates and initializes a new ReplaceStringsTransform.
func NewReplaceStringsTransform(data []byte) (TransformConfig, error) {
	cfg := &ReplaceStringsTransformConfig{}
	err := json.Unmarshal(data, cfg)
	if err != nil {
		return nil, err
	}

	// Convert config replacements to transform replacements
	replacements := make([]transformer.Replacement, 0, len(cfg.ReplaceStrings.Replacements))
	for _, replaceString := range cfg.ReplaceStrings.Replacements {
		replacements = append(replacements, transformer.Replacement{
			Src:     replaceString.Find,
			Dest:    replaceString.Replace,
			IsRegex: replaceString.Regex,
		})
	}

	// apply default content types if not set
	if cfg.ContentTypes == nil {
		cfg.ContentTypes = TextContentTypes
	}

	// nil tr will skip the transform
	if len(replacements) > 0 {
		// Use the new multi-replacement transform for efficiency
		cfg.tr = transformer.MultiStringReplacement(replacements)
	}

	return cfg, nil
}
