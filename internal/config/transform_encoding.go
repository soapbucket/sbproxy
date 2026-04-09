// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/transformer"
)

func init() {
	transformLoaderFns[TransformEncoding] = NewEncodingTransform
}

// EncodingTransformConfig holds configuration for encoding transformer.
type EncodingTransformConfig struct {
	BaseTransform

	trEncoding    transformer.Transformer `json:"-"`
	trContentType transformer.Transformer `json:"-"`
}

// Init performs the init operation on the EncodingTransformConfig.
func (t *EncodingTransformConfig) Init(cfg *Config) error {
	// Both FixEncoding and FixContentType are always enabled
	// They are required for transforms to work correctly
	t.trEncoding = transformer.FixEncoding()
	t.trContentType = transformer.FixContentType()
	return t.BaseTransform.Init(cfg)
}

// Apply performs the apply operation on the EncodingTransformConfig.
func (t *EncodingTransformConfig) Apply(resp *http.Response) error {
	if t.isDisabled(resp) {
		return nil
	}

	// Always apply FixEncoding (decompression)
	slog.Debug("applying fix encoding transform", "url", resp.Request.URL)
	if err := t.trEncoding.Modify(resp); err != nil {
		return err
	}

	// Always apply FixContentType (content-type detection and charset conversion)
	slog.Debug("applying fix content type transform", "url", resp.Request.URL)
	if err := t.trContentType.Modify(resp); err != nil {
		return err
	}

	return nil
}

// NewEncodingTransform creates and initializes a new EncodingTransform.
func NewEncodingTransform(data []byte) (TransformConfig, error) {
	cfg := &EncodingTransformConfig{}
	err := json.Unmarshal(data, cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

// NewDefaultEncodingTransform creates and initializes a new DefaultEncodingTransform.
func NewDefaultEncodingTransform(disableEncoding, disableContentType bool) (TransformConfig, error) {
	// Parameters are ignored - both are always enabled
	// This signature is kept for backward compatibility with existing call sites
	cfg := &EncodingTransformConfig{
		trEncoding:    transformer.FixEncoding(),
		trContentType: transformer.FixContentType(),

		BaseTransform: BaseTransform{
			TransformType: TransformEncoding,
		},
	}
	return cfg, nil
}
