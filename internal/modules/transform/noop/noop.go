// Package noop registers the noop/none transform.
package noop

import (
	"encoding/json"
	"net/http"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterTransform("noop", New)
	plugin.RegisterTransform("none", New)
	plugin.RegisterTransform("", New)
}

// Config holds configuration for the noop transform.
type Config struct {
	Type string `json:"type"`
}

// New creates a new noop transform.
func New(_ json.RawMessage) (plugin.TransformHandler, error) {
	return &noopTransform{}, nil
}

type noopTransform struct{}

func (n *noopTransform) Type() string                    { return "noop" }
func (n *noopTransform) Apply(_ *http.Response) error    { return nil }
