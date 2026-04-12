// Package javascript registers the javascript minification transform.
package javascript

import (
	"encoding/json"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/transformer"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterTransform("javascript", New)
}

// Config holds configuration for the javascript minification transform.
type Config struct {
	Type                string   `json:"type"`
	NumberPrecision     int      `json:"number_precision,omitempty"`
	ChangeVariableNames bool     `json:"change_variable_names,omitempty"`
	SupportedVersion    int      `json:"supported_version,omitempty"`
	ContentTypes        []string `json:"content_types,omitempty"`
}

// javascriptTransform implements plugin.TransformHandler.
type javascriptTransform struct {
	tr transformer.Transformer
}

// New creates a new javascript minification transform.
func New(data json.RawMessage) (plugin.TransformHandler, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &javascriptTransform{
		tr: transformer.MinifyJavascript(transformer.MinifyJavascriptOptions{
			Precision:    cfg.NumberPrecision,
			KeepVarNames: !cfg.ChangeVariableNames,
			Version:      cfg.SupportedVersion,
		}),
	}, nil
}

func (j *javascriptTransform) Type() string                    { return "javascript" }
func (j *javascriptTransform) Apply(resp *http.Response) error { return j.tr.Modify(resp) }
