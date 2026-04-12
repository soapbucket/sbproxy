// Package proxy defines the ProxyConfig interface that decouples the streaming
// proxy from the concrete Config struct in internal/config. This enables moving
// the streaming proxy and its support files out of config/ into their own package.
package proxy

import (
	"net/http"

	"github.com/soapbucket/sbproxy/internal/middleware/compression"
	"github.com/soapbucket/sbproxy/internal/middleware/cors"
	"github.com/soapbucket/sbproxy/internal/middleware/hsts"
	"github.com/soapbucket/sbproxy/internal/middleware/modifier"
)

// ProxyConfig is the interface that the streaming proxy requires from an origin
// configuration. It decouples the proxy handler from the concrete Config struct,
// enabling the streaming proxy files to move out of internal/config/ into their
// own package.
//
// Config-package types (ProxyHeaderConfig, ProxyProtocolConfig, etc.) are
// returned as interface{} because they live in internal/config/ and cannot be
// imported here without creating a cycle. The streaming proxy type-asserts
// these to the concrete config types. When the proxy moves into this package
// those types will be extracted to a shared package and the signatures updated.
type ProxyConfig interface {
	// ---- Identity ----

	// GetID returns the origin config identifier for logging and metrics.
	GetID() string

	// GetHostname returns the origin hostname.
	GetHostname() string

	// ---- Proxy lifecycle ----

	// GetRewriteFn returns the rewrite function that transforms outgoing proxy
	// requests. Returns nil if no rewrite is needed.
	GetRewriteFn() interface{}

	// GetTransport returns the HTTP round-tripper for proxied requests.
	GetTransport() http.RoundTripper

	// GetModifyResponseFn returns the function that post-processes upstream
	// responses. Returns nil if no modification is needed.
	// Concrete type: config.ModifyResponseFn (func(*http.Response) error).
	GetModifyResponseFn() interface{}

	// GetErrorHandlerFn returns the error handler invoked on transport failures.
	// Concrete type: config.ErrorHandlerFn.
	GetErrorHandlerFn() interface{}

	// GetHandler returns the action's HTTP handler (e.g., for WebSocket delegation).
	GetHandler() http.Handler

	// IsProxy reports whether this config's action is a reverse proxy.
	IsProxy() bool

	// ---- Protocol config ----
	// Returns never-nil pointers to config-package structs, typed as interface{}
	// to avoid importing internal/config.

	// ProxyHeadersCfg returns *config.ProxyHeaderConfig (never nil).
	ProxyHeadersCfg() interface{}

	// ProxyProtocolCfg returns *config.ProxyProtocolConfig (never nil).
	ProxyProtocolCfg() interface{}

	// StreamingProxyCfg returns *config.StreamingProxyConfig (never nil).
	StreamingProxyCfg() interface{}

	// ---- Feature config (nil = disabled) ----

	// CompressionCfg returns compression config, or nil if disabled.
	CompressionCfg() *compression.Config

	// CORSCfg returns CORS config, or nil if disabled.
	CORSCfg() *cors.Config

	// HSTSCfg returns HSTS config, or nil if disabled.
	HSTSCfg() *hsts.Config

	// ProxyStatusCfg returns proxy status config, or nil if disabled.
	ProxyStatusCfg() *ProxyStatusConfig

	// ProblemDetailsCfg returns *config.ProblemDetailsConfig, or nil if disabled.
	ProblemDetailsCfg() interface{}

	// URINormalizationCfg returns *config.URINormalizationConfig, or nil if disabled.
	URINormalizationCfg() interface{}

	// HTTPPriorityCfg returns *config.HTTPPriorityConfig, or nil if disabled.
	HTTPPriorityCfg() interface{}

	// ClientHintsCfg returns *config.ClientHintsConfig, or nil if disabled.
	ClientHintsCfg() interface{}

	// PrioritySchedulerCfg returns *config.PrioritySchedulerConfig, or nil if disabled.
	PrioritySchedulerCfg() interface{}

	// MessageSignaturesCfg returns *config.HTTPMessageSignatureConfig, or nil if disabled.
	MessageSignaturesCfg() interface{}

	// ---- Request pipeline ----

	// GetRequestModifiers returns the request modifiers applied to outgoing requests.
	GetRequestModifiers() modifier.RequestModifiers

	// ServeErrorPage attempts to serve a custom error page for the given status.
	// Returns true if an error page was served, false otherwise.
	ServeErrorPage(w http.ResponseWriter, r *http.Request, statusCode int, err error) bool

	// ---- Action access ----

	// ActionCfg returns the underlying action config.
	// Used to extract shadow transport via type assertion.
	ActionCfg() interface{}
}
