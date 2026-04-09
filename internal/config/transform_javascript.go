// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"

	"github.com/soapbucket/sbproxy/internal/transformer"
)

func init() {
	transformLoaderFns[TransformJavascript] = NewJavascriptTransform
}

// JavascriptTransformConfig holds configuration for javascript transformer.
type JavascriptTransformConfig struct {
	JavascriptTransform
}

// NewJavascriptTransform creates and initializes a new JavascriptTransform.
func NewJavascriptTransform(data []byte) (TransformConfig, error) {
	cfg := &JavascriptTransformConfig{}
	err := json.Unmarshal(data, cfg)
	if err != nil {
		return nil, err
	}

	cfg.tr = transformer.MinifyJavascript(transformer.MinifyJavascriptOptions{
		Precision:    cfg.NumberPrecision,
		KeepVarNames: !cfg.ChangeVariableNames,
		Version:      cfg.SupportedVersion,
	})

	// apply default content types if not set
	if cfg.ContentTypes == nil {
		cfg.ContentTypes = JavaScriptContentTypes
	}

	return cfg, nil
}
