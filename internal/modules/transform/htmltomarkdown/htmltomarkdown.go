// Package htmltomarkdown registers the html_to_markdown transform.
package htmltomarkdown

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/transformer"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterTransform("html_to_markdown", New)
}

// Config holds configuration for the html_to_markdown transform.
type Config struct {
	Type                    string `json:"type"`
	TokenCounting           bool   `json:"token_counting,omitempty"`
	AcceptHeaderNegotiation bool   `json:"accept_header_negotiation,omitempty"`
	TokenEstimate           float64 `json:"token_estimate,omitempty"`
	MaxBodySize             int64  `json:"max_body_size,omitempty"`
}

// htmlToMarkdownTransform implements plugin.TransformHandler.
type htmlToMarkdownTransform struct {
	tr          transformer.Transformer
	maxBodySize int64
	cfg         Config
}

// New creates a new html_to_markdown transform.
func New(data json.RawMessage) (plugin.TransformHandler, error) {
	cfg := Config{
		AcceptHeaderNegotiation: true,
		TokenEstimate:           1.3,
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	opts := transformer.MarkdownOptions{
		TokenCounting:           cfg.TokenCounting,
		AcceptHeaderNegotiation: cfg.AcceptHeaderNegotiation,
		TokenEstimate:           cfg.TokenEstimate,
	}

	return &htmlToMarkdownTransform{
		tr:          transformer.ConvertMarkdown(opts),
		maxBodySize: cfg.MaxBodySize,
		cfg:         cfg,
	}, nil
}

func (h *htmlToMarkdownTransform) Type() string { return "html_to_markdown" }
func (h *htmlToMarkdownTransform) Apply(resp *http.Response) error {
	if h.tr == nil {
		return nil
	}

	// Memory guard: skip transform if response body exceeds max_body_size
	const defaultThreshold = 10 * 1024 * 1024 // 10MB
	maxSize := h.maxBodySize
	if maxSize == 0 {
		maxSize = defaultThreshold
	}
	if maxSize > 0 && resp.ContentLength > 0 && resp.ContentLength > maxSize {
		slog.Warn("skipping HTML-to-Markdown transform: response body exceeds max_body_size",
			"content_length", resp.ContentLength,
			"max_body_size", maxSize)
		return nil
	}

	slog.Debug("applying HTMLToMarkdown transform")
	return h.tr.Modify(resp)
}
