// Package template registers the template transform.
package template

import (
	"encoding/json"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/transformer"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterTransform("template", New)
}

// Config holds configuration for the template transform.
type Config struct {
	Type     string      `json:"type"`
	Template string      `json:"template"`
	Data     interface{} `json:"data"`
}

// templateTransform implements plugin.TransformHandler.
type templateTransform struct {
	tr transformer.Transformer
}

// New creates a new template transform.
func New(data json.RawMessage) (plugin.TransformHandler, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &templateTransform{
		tr: transformer.ApplyTemplate(cfg.Template, cfg.Data),
	}, nil
}

func (t *templateTransform) Type() string                    { return "template" }
func (t *templateTransform) Apply(resp *http.Response) error { return t.tr.Modify(resp) }
