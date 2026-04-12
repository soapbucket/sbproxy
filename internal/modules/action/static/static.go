// Package static provides a static-content action module that serves a
// pre-configured response body with custom headers and status code.
// Registers under "static".
package static

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterAction("static", New)
}

// Config holds static action configuration.
type Config struct {
	StatusCode  int               `json:"status_code,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	BodyBase64  string            `json:"body_base64,omitempty"`
	Body        string            `json:"body,omitempty"`
	JSONBody    json.RawMessage   `json:"json_body,omitempty"`
}

// Handler is the static action handler.
type Handler struct {
	statusCode  int
	contentType string
	headers     map[string]string
	body        []byte
}

// New is the ActionFactory for the static module.
func New(raw json.RawMessage) (plugin.ActionHandler, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("static: parse config: %w", err)
	}

	h := &Handler{}

	h.statusCode = cfg.StatusCode
	if h.statusCode == 0 {
		h.statusCode = http.StatusOK
	}

	h.contentType = cfg.ContentType
	if h.contentType == "" {
		h.contentType = "text/plain; charset=utf-8"
	}

	h.headers = cfg.Headers

	// Resolve body: BodyBase64 > JSONBody > Body.
	switch {
	case cfg.BodyBase64 != "":
		decoded, err := base64.StdEncoding.DecodeString(cfg.BodyBase64)
		if err != nil {
			return nil, fmt.Errorf("static: decode body_base64: %w", err)
		}
		h.body = decoded
	case len(cfg.JSONBody) > 0:
		h.body = cfg.JSONBody
		if h.contentType == "text/plain; charset=utf-8" {
			h.contentType = "application/json"
		}
	case cfg.Body != "":
		h.body = []byte(cfg.Body)
	}

	return h, nil
}

// Type returns the action type name.
func (h *Handler) Type() string { return "static" }

// ServeHTTP writes the pre-configured static response.
func (h *Handler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	header := w.Header()
	header.Set("Content-Type", h.contentType)
	for k, v := range h.headers {
		header.Set(k, v)
	}
	w.WriteHeader(h.statusCode)
	if len(h.body) > 0 {
		_, _ = io.Copy(w, bytes.NewReader(h.body))
	}
}
