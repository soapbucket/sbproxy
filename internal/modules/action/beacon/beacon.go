// Package beacon provides a tracking-pixel / analytics beacon action module.
// When empty_gif is true it responds with a 1x1 transparent GIF; otherwise it
// serves configurable static content. Registers itself under the "beacon" name.
package beacon

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

// emptyGIF1x1 is a base64-encoded 1x1 transparent GIF image (43 bytes).
const emptyGIF1x1 = "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"

func init() {
	plugin.RegisterAction("beacon", New)
}

// Config holds beacon action configuration.
type Config struct {
	// Static response fields
	StatusCode  int               `json:"status_code,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	BodyBase64  string            `json:"body_base64,omitempty"`
	Body        string            `json:"body,omitempty"`
	JSONBody    json.RawMessage   `json:"json_body,omitempty"`

	// EmptyGIF, when true, serves a 1x1 transparent GIF pixel.
	EmptyGIF bool `json:"empty_gif,omitempty"`
}

// Handler is the beacon action handler.
type Handler struct {
	cfg Config

	// resolved at construction time
	statusCode  int
	contentType string
	headers     map[string]string
	body        []byte
}

// New is the ActionFactory for the beacon module.
func New(raw json.RawMessage) (plugin.ActionHandler, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("beacon: parse config: %w", err)
	}

	h := &Handler{cfg: cfg}

	// Apply EmptyGIF defaults.
	if cfg.EmptyGIF {
		if cfg.BodyBase64 == "" {
			cfg.BodyBase64 = emptyGIF1x1
		}
		if cfg.ContentType == "" {
			cfg.ContentType = "image/gif"
		}
		if cfg.StatusCode == 0 {
			cfg.StatusCode = http.StatusOK
		}
	}

	// Resolve status code.
	if cfg.StatusCode == 0 {
		h.statusCode = http.StatusOK
	} else {
		h.statusCode = cfg.StatusCode
	}

	// Resolve content type.
	if cfg.ContentType != "" {
		h.contentType = cfg.ContentType
	} else {
		h.contentType = "text/plain; charset=utf-8"
	}

	// Copy headers.
	h.headers = cfg.Headers

	// Resolve body: BodyBase64 > JSONBody > Body.
	switch {
	case cfg.BodyBase64 != "":
		decoded, err := base64.StdEncoding.DecodeString(cfg.BodyBase64)
		if err != nil {
			return nil, fmt.Errorf("beacon: decode body_base64: %w", err)
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
func (h *Handler) Type() string { return "beacon" }

// ServeHTTP serves the pre-resolved static/beacon response.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
