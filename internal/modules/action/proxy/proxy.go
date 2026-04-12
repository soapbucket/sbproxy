// Package proxy implements the reverse proxy action as a self-contained leaf module.
//
// It registers itself into the pkg/plugin registry via init() under the name "proxy".
// The action forwards incoming HTTP requests to a configured upstream URL with full
// control over connection pooling, TLS, retries, and URL rewriting.
//
// This package replaces the adapter-wrapped proxy in internal/modules/action/actions.go.
package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"

	internaltransport "github.com/soapbucket/sbproxy/internal/engine/transport"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterAction("proxy", New)
}

// ErrInvalidURL is returned when the proxy URL is missing or malformed.
var ErrInvalidURL = errors.New("proxy: url is required and must include scheme and host")

// Handler is the proxy action handler. It implements plugin.ReverseProxyAction.
type Handler struct {
	cfg       Config
	targetURL *url.URL
	tr        http.RoundTripper
}

// New is the ActionFactory for the proxy module.
func New(raw json.RawMessage) (plugin.ActionHandler, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("proxy: parse config: %w", err)
	}

	if cfg.URL == "" {
		return nil, ErrInvalidURL
	}

	targetURL, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("proxy: invalid url %q: %w", cfg.URL, err)
	}
	if targetURL.Scheme == "" || targetURL.Host == "" {
		return nil, ErrInvalidURL
	}

	tr := internaltransport.NewTransportFromConfig(cfg.connectionConfig(), cfg.URL)

	if cfg.SkipTLSVerifyHost {
		slog.Warn("CRITICAL SECURITY WARNING: TLS certificate verification is disabled",
			"origin", cfg.URL,
			"connection_type", "proxy",
			"risk", "man-in-the-middle attacks possible",
			"recommendation", "enable TLS verification in production environments")
	}

	if len(raw) > 0 {
		// Log enterprise fields that are silently ignored.
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err == nil {
			if _, ok := obj["canary"]; ok {
				slog.Info("proxy: canary routing is an enterprise feature, ignoring canary config")
			}
			if _, ok := obj["shadow"]; ok {
				slog.Info("proxy: traffic shadowing is an enterprise feature, ignoring shadow config")
			}
		}
	}

	return &Handler{cfg: cfg, targetURL: targetURL, tr: tr}, nil
}

// Type returns the action type name.
func (h *Handler) Type() string { return "proxy" }

// ServeHTTP is required by plugin.ActionHandler. The proxy action uses the
// ReverseProxyAction path (Rewrite + Transport), so ServeHTTP is not called directly.
func (h *Handler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "proxy: direct serving not supported; use reverse proxy path", http.StatusInternalServerError)
}

// Rewrite satisfies plugin.ReverseProxyAction. It rewrites the outbound request
// URL to the configured upstream target.
func (h *Handler) Rewrite(pr *httputil.ProxyRequest) {
	u := pr.In.URL

	slog.Debug("proxy: applying rewrite", "target_url", h.targetURL.String(), "url", u.String())

	targetURL := &url.URL{
		Scheme: h.targetURL.Scheme,
		Host:   h.targetURL.Host,
	}

	if h.cfg.StripBasePath {
		targetURL.Path = u.Path
	} else {
		// Append incoming path to target base path.
		// If incoming path is "/" and target has a non-root path, use target path only.
		if u.Path == "/" && h.targetURL.Path != "" && h.targetURL.Path != "/" {
			targetURL.Path = h.targetURL.Path
		} else {
			targetURL.Path = h.targetURL.Path + u.Path
		}
	}

	if h.cfg.PreserveQuery {
		targetURL.RawQuery = u.RawQuery
	} else {
		if u.RawQuery != "" || h.targetURL.RawQuery != "" {
			query := h.targetURL.Query()
			for k, vs := range u.Query() {
				for _, v := range vs {
					query.Add(k, v)
				}
			}
			targetURL.RawQuery = query.Encode()
		}
	}

	pr.Out.URL = targetURL

	req := pr.Out
	hostname := targetURL.Host
	req.Host = hostname
	req.Header.Set("Host", hostname)

	if h.cfg.AltHostname != "" {
		req.Host = h.cfg.AltHostname
		req.Header.Set("Host", h.cfg.AltHostname)
	}

	if h.cfg.DisableCompression {
		req.Header.Del("Accept-Encoding")
	} else {
		// Forward the client's Accept-Encoding to the upstream backend so the
		// response encoding matches what the client can decode. Hardcoding all
		// algorithms (br, zstd, gzip, ...) causes the backend to send brotli
		// to a client that only asked for gzip, resulting in garbled output.
		clientAE := pr.In.Header.Get("Accept-Encoding")
		if clientAE != "" {
			req.Header.Set("Accept-Encoding", clientAE)
		} else {
			// No client preference: request uncompressed from upstream.
			// The proxy's own compressor middleware will compress for the client.
			req.Header.Set("Accept-Encoding", "identity")
		}
	}

	slog.Debug("proxy: rewritten request", "url", req.URL.String())
}

// Transport satisfies plugin.ReverseProxyAction and returns the upstream transport.
func (h *Handler) Transport() http.RoundTripper { return h.tr }

// ModifyResponse satisfies plugin.ReverseProxyAction. The proxy action does not
// perform response modifications at this level.
func (h *Handler) ModifyResponse(_ *http.Response) error { return nil }

// ErrorHandler satisfies plugin.ReverseProxyAction and logs upstream errors.
func (h *Handler) ErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("proxy: upstream error",
		"url", r.URL.String(),
		"error", err)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = w.Write([]byte(strconv.Itoa(http.StatusBadGateway) + " " + http.StatusText(http.StatusBadGateway)))
}

// Provision receives origin-level context after config loading.
// Satisfies pkg/plugin.Provisioner (optional lifecycle interface).
func (h *Handler) Provision(ctx plugin.PluginContext) error {
	_ = ctx // No origin-level context needed for basic proxy.
	return nil
}

// Validate checks that the configuration is valid.
// Satisfies pkg/plugin.Validator (optional lifecycle interface).
func (h *Handler) Validate() error {
	if h.cfg.URL == "" {
		return ErrInvalidURL
	}
	if h.targetURL == nil || h.targetURL.Scheme == "" || h.targetURL.Host == "" {
		return ErrInvalidURL
	}
	return nil
}
