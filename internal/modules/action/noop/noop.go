// Package noop provides a no-op action module that responds with 204 No Content.
// It registers itself into the pkg/plugin registry via init() under both the
// "noop" name and the empty string (TypeNone).
package noop

import (
	"encoding/json"
	"net/http"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterAction("noop", New)
	plugin.RegisterAction("", New) // TypeNone is empty string
}

// Handler is the noop action handler.
type Handler struct{}

// New is the ActionFactory for the noop module. It ignores any configuration
// and returns a shared Handler.
func New(_ json.RawMessage) (plugin.ActionHandler, error) {
	return &Handler{}, nil
}

// Type returns the action type name.
func (h *Handler) Type() string { return "noop" }

// ServeHTTP responds with 204 No Content, discarding the request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}
