// Package echo provides an echo action module that returns a JSON representation
// of the incoming request. Useful for debugging, testing, and API exploration.
//
// It registers itself into the pkg/plugin registry via init() under the name "echo".
package echo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterAction("echo", New)
}

// Config holds the configuration for the echo action.
type Config struct {
	// IncludeContext, when true, embeds the request context data (origin ID,
	// workspace, session info, etc.) in the response under "request_data".
	IncludeContext bool `json:"include_context,omitempty"`

	// originID and workspaceID are populated by Provision from PluginContext.
	originID    string
	workspaceID string
}

// Handler is the echo action handler.
type Handler struct {
	cfg Config
}

// New is the ActionFactory for the echo module. It parses JSON configuration
// and returns a new Handler ready for Provision/Validate.
func New(raw json.RawMessage) (plugin.ActionHandler, error) {
	h := &Handler{}
	if err := json.Unmarshal(raw, &h.cfg); err != nil {
		return nil, fmt.Errorf("echo: parse config: %w", err)
	}
	return h, nil
}

// Type returns the action type name used in sb.yml configuration.
func (h *Handler) Type() string { return "echo" }

// Provision receives origin-level context after config loading. This satisfies
// pkg/plugin.Provisioner, which the bridge calls after factory creation.
func (h *Handler) Provision(ctx plugin.PluginContext) error {
	h.cfg.originID = ctx.OriginID
	h.cfg.workspaceID = ctx.WorkspaceID
	return nil
}

// Validate checks that the configuration is valid. The echo action has no
// required fields so validation always succeeds.
func (h *Handler) Validate() error { return nil }

// ServeHTTP handles the request by writing a JSON body that mirrors the
// incoming request's method, URL, headers, body, and timing. This satisfies
// pkg/plugin.ActionHandler and is called directly (not via reverse proxy).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var bodyBytes []byte
	if r.Body != nil {
		defer r.Body.Close()
		var err error
		if bodyBytes, err = io.ReadAll(r.Body); err != nil {
			http.Error(w, fmt.Sprintf("echo: read body: %v", err), http.StatusInternalServerError)
			return
		}
	}

	requestMap := map[string]any{
		"method":            r.Method,
		"url":               r.URL.String(),
		"host":              r.Host,
		"proto":             r.Proto,
		"remote_addr":       r.RemoteAddr,
		"content_length":    r.ContentLength,
		"transfer_encoding": r.TransferEncoding,
		"headers":           r.Header,
		"cookies":           r.Cookies(),
	}
	if len(bodyBytes) > 0 {
		requestMap["body"] = string(bodyBytes)
	}
	if r.Form != nil {
		requestMap["form_params"] = r.Form
	}

	payload := map[string]any{
		"timestamp": time.Now().Format(time.RFC3339),
		"request":   requestMap,
	}

	if h.cfg.IncludeContext {
		payload["context"] = map[string]any{
			"origin_id":    h.cfg.originID,
			"workspace_id": h.cfg.workspaceID,
		}
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, fmt.Sprintf("echo: marshal response: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(jsonBody)))
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, bytes.NewReader(jsonBody))
}
