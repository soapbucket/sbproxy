// Package grpc implements the gRPC proxy action as a self-contained leaf module.
//
// It registers itself into the pkg/plugin registry via init() under the name "grpc".
// The action forwards gRPC (HTTP/2) requests to a configured upstream, supporting
// unary, server-streaming, client-streaming, and bidirectional streaming RPCs with
// header propagation and deadline forwarding.
//
// This package replaces the adapter-wrapped grpc in internal/modules/action/actions.go.
package grpc

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	internaltransport "github.com/soapbucket/sbproxy/internal/engine/transport"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterAction("grpc", New)
}

const (
	defaultMaxRecvMsgSize = 4 * 1024 * 1024 // 4MB
	defaultMaxSendMsgSize = 4 * 1024 * 1024 // 4MB
)

// Handler is the gRPC action handler. It implements plugin.ReverseProxyAction.
type Handler struct {
	cfg       Config
	targetURL *url.URL
	tr        http.RoundTripper
}

// New is the ActionFactory for the grpc module.
func New(raw json.RawMessage) (plugin.ActionHandler, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("grpc: parse config: %w", err)
	}

	if cfg.URL == "" {
		return nil, fmt.Errorf("grpc: url is required")
	}

	targetURL, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("grpc: invalid url: %w", err)
	}

	// Normalize scheme.
	switch targetURL.Scheme {
	case "grpc", "grpcs":
		targetURL.Scheme = "https"
	case "http", "https":
		// OK as-is.
	default:
		return nil, fmt.Errorf("grpc: url must use http://, https://, grpc://, or grpcs:// scheme")
	}

	// Parse JSON to detect explicitly-set defaults.
	var jsonObj map[string]interface{}
	_ = json.Unmarshal(raw, &jsonObj)

	if _, set := jsonObj["strip_base_path"]; !set {
		cfg.StripBasePath = true
	}
	if _, set := jsonObj["preserve_query"]; !set {
		cfg.PreserveQuery = true
	}
	if _, set := jsonObj["forward_metadata"]; !set {
		cfg.ForwardMetadata = true
	}

	if cfg.MaxCallRecvMsgSize == 0 {
		cfg.MaxCallRecvMsgSize = defaultMaxRecvMsgSize
	}
	if cfg.MaxCallSendMsgSize == 0 {
		cfg.MaxCallSendMsgSize = defaultMaxSendMsgSize
	}

	if cfg.HTTP11Only {
		slog.Warn("grpc: HTTP/1.1 only is enabled but gRPC requires HTTP/2; disabling HTTP/1.1 only mode",
			"url", cfg.URL)
	}

	connCfg := cfg.connectionConfig()
	baseTransport := internaltransport.NewTransportFromConfig(connCfg)

	tr := &grpcTransport{
		base:               baseTransport,
		forwardMetadata:    cfg.ForwardMetadata,
		disableCompression: cfg.DisableCompression,
	}

	if cfg.SkipTLSVerifyHost {
		slog.Warn("CRITICAL SECURITY WARNING: TLS certificate verification is disabled",
			"origin", cfg.URL,
			"connection_type", "grpc",
			"risk", "man-in-the-middle attacks possible",
			"recommendation", "enable TLS verification in production environments")
		metric.TLSInsecureSkipVerifyEnabled(cfg.URL, "grpc")
	}

	return &Handler{cfg: cfg, targetURL: targetURL, tr: tr}, nil
}

// Type returns the action type name.
func (h *Handler) Type() string { return "grpc" }

// ServeHTTP is required by plugin.ActionHandler. The gRPC action uses the
// ReverseProxyAction path, so ServeHTTP is not called directly.
func (h *Handler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "grpc: direct serving not supported; use reverse proxy path", http.StatusInternalServerError)
}

// Rewrite satisfies plugin.ReverseProxyAction.
func (h *Handler) Rewrite(pr *httputil.ProxyRequest) {
	req := pr.In.URL
	slog.Debug("grpc: rewriting request", "target_url", h.targetURL.String(), "incoming_path", req.Path)

	targetURL := &url.URL{
		Scheme: h.targetURL.Scheme,
		Host:   h.targetURL.Host,
	}

	if h.cfg.StripBasePath {
		targetURL.Path = req.Path
	} else {
		targetURL.Path = h.targetURL.Path + req.Path
	}

	if h.cfg.PreserveQuery {
		if req.RawQuery != "" || h.targetURL.RawQuery != "" {
			query := h.targetURL.Query()
			for k, vs := range pr.In.URL.Query() {
				for _, v := range vs {
					query.Add(k, v)
				}
			}
			targetURL.RawQuery = query.Encode()
		}
	} else {
		targetURL.RawQuery = h.targetURL.RawQuery
	}

	pr.SetURL(targetURL)

	outReq := pr.Out
	hostname := targetURL.Host
	outReq.Host = hostname
	outReq.Header.Set("Host", hostname)

	contentType := outReq.Header.Get("Content-Type")
	if contentType == "" {
		outReq.Header.Set("Content-Type", "application/grpc")
	} else if h.cfg.EnableGRPCWeb && strings.HasPrefix(contentType, "application/grpc-web") {
		// Keep as-is for gRPC-Web.
	} else if !strings.HasPrefix(contentType, "application/grpc") {
		slog.Debug("grpc: unexpected content-type", "content_type", contentType)
	}

	outReq.Header.Set("TE", "trailers")

	if h.cfg.ForwardMetadata {
		for key, values := range pr.In.Header {
			if strings.HasPrefix(strings.ToLower(key), "grpc-") {
				for _, value := range values {
					outReq.Header.Add(key, value)
				}
			}
		}
	}

	slog.Debug("grpc: request rewritten", "url", outReq.URL.String(),
		"content_type", outReq.Header.Get("Content-Type"))
}

// Transport satisfies plugin.ReverseProxyAction.
func (h *Handler) Transport() http.RoundTripper { return h.tr }

// ModifyResponse satisfies plugin.ReverseProxyAction.
func (h *Handler) ModifyResponse(_ *http.Response) error { return nil }

// ErrorHandler satisfies plugin.ReverseProxyAction.
func (h *Handler) ErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("grpc: upstream error", "url", r.URL.String(), "error", err)
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("grpc-status", "14") // UNAVAILABLE
	w.Header().Set("grpc-message", "upstream connection failed")
	w.WriteHeader(http.StatusBadGateway)
}

// grpcTransport wraps the base transport with gRPC-specific response handling.
type grpcTransport struct {
	base               http.RoundTripper
	forwardMetadata    bool
	disableCompression bool
}

// RoundTrip adds gRPC-specific logic around the base round trip.
func (t *grpcTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	start := time.Now()

	contentType := r.Header.Get("Content-Type")
	isGRPCWeb := strings.HasPrefix(contentType, "application/grpc-web")
	isGRPC := strings.HasPrefix(contentType, "application/grpc") || isGRPCWeb

	if !isGRPC {
		slog.Debug("grpc: non-gRPC content-type detected", "content_type", contentType)
	}

	resp, err := t.base.RoundTrip(r)
	if err != nil {
		slog.Error("grpc: backend request failed", "error", err, "url", r.URL.String())
		return nil, err
	}

	duration := time.Since(start)

	if resp.Header.Get("Content-Type") == "" {
		if isGRPCWeb {
			resp.Header.Set("Content-Type", "application/grpc-web+proto")
		} else {
			resp.Header.Set("Content-Type", "application/grpc")
		}
	}

	if !t.disableCompression {
		resp.Header.Set("grpc-encoding", "gzip, br, snappy, zstd, deflate, identity")
	}

	slog.Debug("grpc: backend request completed",
		"duration", duration,
		"status", resp.StatusCode,
		"grpc_status", resp.Header.Get("grpc-status"),
		"url", r.URL.String())

	return resp, nil
}
