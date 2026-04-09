// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/transformer"
)

func init() {
	transformLoaderFns[TransformHTMLToMarkdown] = NewHTMLToMarkdownTransform
}

var _ TransformConfig = (*HTMLToMarkdownTransformConfig)(nil)

// HTMLToMarkdownTransformConfig configures HTML-to-Markdown conversion
type HTMLToMarkdownTransformConfig struct {
	BaseTransform

	// TokenCounting enables x-markdown-tokens header in response
	TokenCounting bool `json:"token_counting,omitempty"`

	// AcceptHeaderNegotiation only converts if Accept: text/markdown is present
	AcceptHeaderNegotiation bool `json:"accept_header_negotiation,omitempty"`

	// TokenEstimate is tokens per word approximation (default 1.3 for GPT-3 style)
	TokenEstimate float64 `json:"token_estimate,omitempty"`
}

// NewHTMLToMarkdownTransform creates and initializes a new HTMLToMarkdownTransform.
func NewHTMLToMarkdownTransform(data []byte) (TransformConfig, error) {
	t := &HTMLToMarkdownTransformConfig{
		AcceptHeaderNegotiation: true,
		TokenEstimate:           1.3,
	}
	if err := json.Unmarshal(data, t); err != nil {
		return nil, err
	}

	opts := transformer.MarkdownOptions{
		TokenCounting:           t.TokenCounting,
		AcceptHeaderNegotiation: t.AcceptHeaderNegotiation,
		TokenEstimate:           t.TokenEstimate,
	}

	t.tr = transformer.ConvertMarkdown(opts)
	return t, nil
}

// Init initializes the transform
func (t *HTMLToMarkdownTransformConfig) Init(cfg *Config) error {
	slog.Debug("Initializing HTMLToMarkdown transform",
		"token_counting", t.TokenCounting,
		"accept_header_negotiation", t.AcceptHeaderNegotiation)
	return t.BaseTransform.Init(cfg)
}

// Apply applies the transform to the response
func (t *HTMLToMarkdownTransformConfig) Apply(resp *http.Response) error {
	if t.tr == nil || t.isDisabled(resp) {
		return nil
	}

	// Memory guard: skip transform if response body exceeds max_body_size
	maxSize := t.effectiveMaxBodySize()
	if maxSize > 0 && resp.ContentLength > 0 && resp.ContentLength > maxSize {
		slog.Warn("skipping HTML-to-Markdown transform: response body exceeds max_body_size",
			"content_length", resp.ContentLength,
			"max_body_size", maxSize)
		return nil
	}

	slog.Debug("applying HTMLToMarkdown transform")
	return t.tr.Modify(resp)
}

// GetType returns the transform type
func (t *HTMLToMarkdownTransformConfig) GetType() string {
	return TransformHTMLToMarkdown
}
