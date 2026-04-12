// Package redirect provides an HTTP redirect action module. It issues 301/302/303/307/308
// redirects with optional path and query forwarding. Registers under "redirect".
package redirect

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterAction("redirect", New)
}

// Config holds redirect action configuration.
type Config struct {
	URL           string `json:"url"`
	StatusCode    int    `json:"status_code,omitempty"`
	StripBasePath bool   `json:"strip_base_path,omitempty"`
	PreserveQuery bool   `json:"preserve_query,omitempty"`
}

// Handler is the redirect action handler.
type Handler struct {
	cfg Config
}

// New is the ActionFactory for the redirect module.
func New(raw json.RawMessage) (plugin.ActionHandler, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("redirect: parse config: %w", err)
	}

	// Validate URL.
	if cfg.URL == "" {
		return nil, fmt.Errorf("redirect: url is required")
	}

	// Validate status code.
	switch cfg.StatusCode {
	case http.StatusMovedPermanently,  // 301
		http.StatusFound,              // 302
		http.StatusSeeOther,           // 303
		http.StatusTemporaryRedirect,  // 307
		http.StatusPermanentRedirect:  // 308
		// valid
	default:
		return nil, fmt.Errorf("redirect: invalid status code %d (must be 301, 302, 303, 307, or 308)", cfg.StatusCode)
	}

	return &Handler{cfg: cfg}, nil
}

// Type returns the action type name.
func (h *Handler) Type() string { return "redirect" }

// ServeHTTP issues an HTTP redirect.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	target := h.cfg.URL

	if h.cfg.StripBasePath {
		target = strings.TrimSuffix(target, "/") + r.URL.Path
	}

	if h.cfg.PreserveQuery && r.URL.RawQuery != "" {
		if strings.Contains(target, "?") {
			target += "&" + r.URL.RawQuery
		} else {
			target += "?" + r.URL.RawQuery
		}
	}

	body := buildBody(target)
	w.Header().Set("Location", target)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(h.cfg.StatusCode)
	_, _ = fmt.Fprint(w, body)
}

func buildBody(url string) string {
	escaped := strings.NewReplacer("<", "&lt;", ">", "&gt;", "&", "&amp;", `"`, "&#34;").Replace(url)
	return `<!DOCTYPE html>
<html>
<head>
    <title>Redirecting...</title>
    <meta http-equiv="refresh" content="0; url=` + escaped + `">
</head>
<body>
    <p>Redirecting to <a href="` + escaped + `">` + escaped + `</a>...</p>
</body>
</html>`
}
