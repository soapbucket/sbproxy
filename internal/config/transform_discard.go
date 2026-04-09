// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"

	"github.com/soapbucket/sbproxy/internal/transformer"
)

func init() {
	transformLoaderFns[TransformDiscard] = NewDiscardTransform
}

// DiscardTransformConfig holds configuration for discard transformer.
type DiscardTransformConfig struct {
	DiscardTransform
}

// NewDiscardTransform creates and initializes a new DiscardTransform.
func NewDiscardTransform(data []byte) (TransformConfig, error) {
	cfg := &DiscardTransformConfig{}
	err := json.Unmarshal(data, cfg)
	if err != nil {
		return nil, err
	}

	cfg.tr = transformer.Discard(cfg.Bytes)

	return cfg, nil
}
