// Package storage provides a cloud storage action module that serves objects
// from S3, Azure Blob, Google Cloud Storage, Backblaze B2, or OpenStack Swift.
// Registers under "storage".
package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"

	"github.com/soapbucket/sbproxy/internal/engine/transport"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

var (
	errKindRequired   = errors.New("storage: kind is required")
	errBucketRequired = errors.New("storage: bucket is required")
	errInvalidKind    = errors.New("storage: invalid storage kind (must be s3, azure, google, swift, or b2)")
)

var validKinds = map[string]bool{
	"s3":     true,
	"azure":  true,
	"google": true,
	"swift":  true,
	"b2":     true,
}

func init() {
	plugin.RegisterAction("storage", New)
}

// Config holds the cloud storage backend configuration.
type Config struct {
	Kind          string `json:"kind"`
	Bucket        string `json:"bucket"`
	Key           string `json:"key,omitempty"`
	Secret        string `json:"secret,omitempty"`
	Region        string `json:"region,omitempty"`
	ProjectID     string `json:"project_id,omitempty"`
	Account       string `json:"account,omitempty"`
	Scopes        string `json:"scopes,omitempty"`
	TenantName    string `json:"tenant_name,omitempty"`
	TenantAuthURL string `json:"tenant_auth_url,omitempty"`
}

// Handler is the storage action handler. It implements plugin.ReverseProxyAction
// so the proxy engine routes requests through the storage transport.
type Handler struct {
	kind string
	tr   http.RoundTripper
}

// New is the ActionFactory for the storage module.
func New(raw json.RawMessage) (plugin.ActionHandler, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("storage: parse config: %w", err)
	}

	if cfg.Kind == "" {
		slog.Error("storage kind is required")
		return nil, errKindRequired
	}
	if cfg.Bucket == "" {
		slog.Error("storage bucket is required")
		return nil, errBucketRequired
	}
	if !validKinds[cfg.Kind] {
		slog.Error("invalid storage kind", "kind", cfg.Kind)
		return nil, errInvalidKind
	}

	settings := buildSettings(&cfg)
	cache := transport.GetGlobalLocationCache()
	tr := transport.NewStorageWithCache(cfg.Kind, settings, nil, cache)

	slog.Debug("storage config loaded", "kind", cfg.Kind, "bucket", cfg.Bucket)
	return &Handler{kind: cfg.Kind, tr: tr}, nil
}

func buildSettings(cfg *Config) transport.Settings {
	s := transport.Settings{
		"bucket": cfg.Bucket,
	}
	if cfg.Key != "" {
		s["key"] = cfg.Key
	}
	if cfg.Secret != "" {
		s["secret"] = cfg.Secret
	}
	if cfg.Region != "" {
		s["region"] = cfg.Region
	}
	if cfg.ProjectID != "" {
		s["projectId"] = cfg.ProjectID
	}
	if cfg.Account != "" {
		s["account"] = cfg.Account
	}
	if cfg.Scopes != "" {
		s["scopes"] = cfg.Scopes
	}
	if cfg.TenantName != "" {
		s["tenant"] = cfg.TenantName
	}
	if cfg.TenantAuthURL != "" {
		s["tenantAuthURL"] = cfg.TenantAuthURL
	}
	return s
}

// Type returns the action type name.
func (h *Handler) Type() string { return "storage" }

// ServeHTTP is required by plugin.ActionHandler. Storage uses the reverse proxy
// path (Transport), so ServeHTTP is not called directly by the engine.
func (h *Handler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "storage: direct serving not supported; use reverse proxy path", http.StatusInternalServerError)
}

// Rewrite satisfies plugin.ReverseProxyAction. Storage does not rewrite requests.
func (h *Handler) Rewrite(_ *httputil.ProxyRequest) {}

// Transport satisfies plugin.ReverseProxyAction and returns the cloud storage transport.
func (h *Handler) Transport() http.RoundTripper { return h.tr }

// ModifyResponse satisfies plugin.ReverseProxyAction. Storage does not modify responses.
func (h *Handler) ModifyResponse(_ *http.Response) error { return nil }

// ErrorHandler satisfies plugin.ReverseProxyAction. Storage does not provide a custom error handler.
func (h *Handler) ErrorHandler(_ http.ResponseWriter, _ *http.Request, _ error) {}
