// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"

	"github.com/soapbucket/sbproxy/internal/transformer"
)

func init() {
	transformLoaderFns[TransformCSS] = NewCSSTransform
}

// CSSTransformConfig holds configuration for css transformer.
type CSSTransformConfig struct {
	CSSTransform
}

// NewCSSTransform creates and initializes a new CSSTransform.
func NewCSSTransform(data []byte) (TransformConfig, error) {
	cfg := &CSSTransformConfig{}
	err := json.Unmarshal(data, cfg)
	if err != nil {
		return nil, err
	}

	cfg.tr = transformer.MinifyCSS(transformer.MinifyCSSOptions{
		Precision: cfg.Precision,
		Inline:    cfg.Inline,
		Version:   cfg.Version,
	})

	// apply default content types if not set
	if cfg.ContentTypes == nil {
		cfg.ContentTypes = CSSContentTypes
	}

	return cfg, nil
}
