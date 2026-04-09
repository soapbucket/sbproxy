// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"

	"github.com/soapbucket/sbproxy/internal/transformer"
)

func init() {
	transformLoaderFns[TransformTemplate] = NewTemplateTransformConfig
}

// TemplateTransformConfig holds configuration for template transformer.
type TemplateTransformConfig struct {
	TemplateTransform
}

// NewTemplateTransformConfig creates and initializes a new TemplateTransformConfig.
func NewTemplateTransformConfig(data []byte) (TransformConfig, error) {
	config := &TemplateTransformConfig{}
	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}

	// apply default content types if not set
	if config.ContentTypes == nil {
		config.ContentTypes = JSONContentTypes
	}

	config.tr = transformer.ApplyTemplate(config.Template, config.Data)
	return config, nil
}
