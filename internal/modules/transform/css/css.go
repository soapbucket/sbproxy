// Package css registers the css minification transform.
package css

import (
	"encoding/json"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/transformer"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterTransform("css", New)
}

var defaultContentTypes = []string{"text/css"}

// Config holds configuration for the CSS minification transform.
type Config struct {
	Type         string   `json:"type"`
	Precision    int      `json:"precision,omitempty"`
	Inline       bool     `json:"inline,omitempty"`
	Version      int      `json:"version,omitempty"`
	ContentTypes []string `json:"content_types,omitempty"`
}

// cssTransform implements plugin.TransformHandler.
type cssTransform struct {
	tr           transformer.Transformer
	contentTypes []string
}

// New creates a new CSS minification transform.
func New(data json.RawMessage) (plugin.TransformHandler, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	ct := cfg.ContentTypes
	if ct == nil {
		ct = defaultContentTypes
	}
	return &cssTransform{
		tr: transformer.MinifyCSS(transformer.MinifyCSSOptions{
			Precision: cfg.Precision,
			Inline:    cfg.Inline,
			Version:   cfg.Version,
		}),
		contentTypes: ct,
	}, nil
}

func (c *cssTransform) Type() string { return "css" }
func (c *cssTransform) Apply(resp *http.Response) error {
	return c.tr.Modify(resp)
}
