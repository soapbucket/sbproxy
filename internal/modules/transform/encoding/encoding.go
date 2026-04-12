// Package encoding registers the encoding transform.
package encoding

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/transformer"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterTransform("encoding", New)
}

// Config holds configuration for the encoding transform.
type Config struct {
	Type string `json:"type"`
}

// encodingTransform implements plugin.TransformHandler.
type encodingTransform struct {
	trEncoding    transformer.Transformer
	trContentType transformer.Transformer
}

// New creates a new encoding transform.
func New(data json.RawMessage) (plugin.TransformHandler, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &encodingTransform{
		trEncoding:    transformer.FixEncoding(),
		trContentType: transformer.FixContentType(),
	}, nil
}

func (e *encodingTransform) Type() string { return "encoding" }
func (e *encodingTransform) Apply(resp *http.Response) error {
	slog.Debug("applying fix encoding transform", "url", resp.Request.URL)
	if err := e.trEncoding.Modify(resp); err != nil {
		return err
	}
	slog.Debug("applying fix content type transform", "url", resp.Request.URL)
	return e.trContentType.Modify(resp)
}
