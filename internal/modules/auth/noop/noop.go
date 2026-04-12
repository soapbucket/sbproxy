// Package noop registers the noop/none auth provider.
package noop

import (
	"encoding/json"
	"net/http"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterAuth("noop", New)
	plugin.RegisterAuth("none", New)
}

// Config holds configuration for the noop auth provider.
type Config struct {
	Type     string `json:"type"`
	Disabled bool   `json:"disabled,omitempty"`
}

// New creates a new noop auth provider that allows all requests through.
func New(_ json.RawMessage) (plugin.AuthProvider, error) {
	return &noopAuth{}, nil
}

type noopAuth struct{}

func (n *noopAuth) Type() string { return "noop" }

func (n *noopAuth) Wrap(next http.Handler) http.Handler { return next }
