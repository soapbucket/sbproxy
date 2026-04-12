// Package discard registers the discard transform.
package discard

import (
	"encoding/json"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/transformer"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterTransform("discard", New)
}

// Config holds configuration for the discard transform.
type Config struct {
	Type  string `json:"type"`
	Bytes int    `json:"bytes"`
}

// discardTransform implements plugin.TransformHandler.
type discardTransform struct {
	tr transformer.Transformer
}

// New creates a new discard transform.
func New(data json.RawMessage) (plugin.TransformHandler, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &discardTransform{
		tr: transformer.Discard(cfg.Bytes),
	}, nil
}

func (d *discardTransform) Type() string                   { return "discard" }
func (d *discardTransform) Apply(resp *http.Response) error { return d.tr.Modify(resp) }
