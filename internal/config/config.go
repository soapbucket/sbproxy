// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
//
// MAINTAINABILITY AUDIT (2026-04-11)
//
// Config struct field count: 79 (including 4 sync primitives mixed with data fields).
//
// Sync primitives mixed with data fields:
//   - onLoadLastExecuted (atomic.Value)
//   - onLoadMu (sync.Mutex) + onLoadReloading (bool)
//   - envMapOnce (sync.Once)
//   - originCtxOnce (sync.Once)
//
// Recommendation: decompose into sub-configs when practical:
//  1. IdentityConfig    - ID, Hostname, WorkspaceID, ClusterID, ClusterType, Version, Revision, Environment, Tags, OriginName
//  2. SecurityConfig    - Auth, Policies, CORS, HSTS, CSRF, BotDetection, ThreatProtection, WAF, IPFilter, MessageSignatures
//  3. TransportConfig   - Action, ForwardRules, FallbackOrigin, FailsafeOrigin, MaxConnections, FlushInterval, ProxyHeaders, ProxyProtocol, StreamingProxyConfig, Compression
//  4. CachingConfig     - ResponseCache, ChunkCache, ErrorPages
//  5. ObservabilityConfig - TrafficCapture, Events, Debug, ProxyStatus, RateLimitHeaders, ProblemDetails
//  6. ExtensionsConfig  - Transforms, TransformChains, RequestModifiers, ResponseModifiers, OnLoad, OnRequest, APIVersioning
//  7. SecretsConfig     - Vaults, SecretsMap, vaultManager, Secrets, Variables
//
// Function pointer count for import-cycle avoidance: 4
//   - FallbackLoader         (config -> configloader)
//   - OriginConfigLoader     (config -> configloader)
//   - EmbeddedConfigLoader   (config -> configloader)
//   - ServerContextFn        (config -> server)
//
// These are set by configloader at init time to break config <-> configloader import cycles.
// Consider introducing an interface (e.g., ConfigResolver) in a shared package to reduce coupling.
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/middleware/callback"
	"github.com/soapbucket/sbproxy/internal/middleware/forward"
	"github.com/soapbucket/sbproxy/internal/middleware/modifier"
	"github.com/soapbucket/sbproxy/internal/middleware/rule"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/vault"
)

// noCopy is embedded in structs that must not be copied after first use.
// It implements sync.Locker so `go vet` reports copies via the -copylocks check.
type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

// Config holds the complete origin configuration for a proxy endpoint.
type Config struct {
	_ noCopy // Config contains sync primitives and maps; copying is unsafe.

	ID          string   `json:"id"`
	Hostname    string   `json:"hostname"`
	WorkspaceID string   `json:"workspace_id"` // this should not be empty, along with ID and Hostname
	ClusterID   string   `json:"cluster_id,omitempty"`
	ClusterType string   `json:"cluster_type,omitempty"`
	Debug       bool     `json:"debug,omitempty"`
	Version     string   `json:"version"`               // Version string (e.g., "1.0", "2.1.3") - not omitempty
	Revision    string   `json:"revision,omitempty"`    // Immutable runtime revision when available
	Environment string   `json:"environment,omitempty"` // dev, stage, prod (may be extended)
	Tags        []string `json:"tags,omitempty"`        // User-defined tags for filtering and reporting
	OriginName  string   `json:"origin_name,omitempty"` // Origin slug name set during config assembly

	// Serving metadata is populated by the loader. It is not source config.
	ConfigMode   string `json:"-"`
	ConfigReason string `json:"-"`

	Disabled bool `json:"disabled,omitempty"`

	ForceSSL bool `sb_flag:"force_ssl" json:"force_ssl,omitempty"`

	AllowedMethods []string             `json:"allowed_methods,omitempty"`
	RequestRules   rule.RequestRules    `json:"request_rules,omitempty"`
	MustMatchRules bool                 `json:"must_match_rules,omitempty"`
	ForwardRules   forward.ForwardRules `json:"forward_rules,omitempty"`
	FallbackOrigin *FallbackOrigin      `json:"fallback_origin,omitempty"`
	FailsafeOrigin *FailsafeOrigin      `json:"failsafe_origin,omitempty"`

	RequestModifiers  modifier.RequestModifiers  `json:"request_modifiers,omitempty"`
	ResponseModifiers modifier.ResponseModifiers `json:"response_modifiers,omitempty"`

	SessionConfig SessionConfig `json:"session"`

	// ResponseCache configures action-level response caching
	ResponseCache *ActionResponseCache `json:"response_cache,omitempty"`

	// ChunkCache configures unified chunk caching (URL and signature-based)
	ChunkCache *ChunkCacheConfig `json:"chunk_cache,omitempty"`

	MaxConnections int        `json:"max_connections,omitempty" validate:"max_value=10000"`
	APIConfig      *APIConfig `json:"api_config,omitempty"`

	// the following are used for parent/child relationships
	Parent             *Config `json:"parent,omitempty"`
	DisableApplyParent bool    `json:"disable_apply_parent,omitempty"`

	CookieJarFn        CookieJarFn `json:"-"` // function to create a cookie jar for the request
	cookieJarTransport TransportFn `json:"-"` // wrapped transport with cookie jar support

	DisableCompression             bool            `sb_flag:"disable_compression" json:"disableCompression,omitempty"`
	DisableHTTP3                   bool            `sb_flag:"disable_http3" json:"disableHTTP3,omitempty"`
	DisableSecurity                bool            `json:"disable_security,omitempty"`
	DisableTransformsByContentType map[string]bool `json:"disable_transforms_by_content_type,omitempty"`
	FlushInterval                  reqctx.Duration `json:"flush_interval,omitempty" validate:"max_value=1m"`

	Action json.RawMessage `json:"action,omitempty"`
	action ActionConfig    `json:"-"`

	Transforms      []json.RawMessage            `json:"transforms,omitempty"`
	TransformChains map[string][]json.RawMessage `json:"transform_chains,omitempty"`
	transforms      []TransformConfig            `json:"-"`

	Auth json.RawMessage `json:"authentication,omitempty"`
	auth AuthConfig      `json:"-"`

	Policies []json.RawMessage `json:"policies,omitempty"`
	policies []PolicyConfig    `json:"-"`

	// Variables are user-defined key-value pairs available in template context as {{ variables.name }}
	// Supports any JSON type including nested objects and arrays
	Variables map[string]any `json:"variables,omitempty"`

	// Vaults defines named vault backends for secret resolution.
	// Each entry maps a vault name to its configuration (type, address, credentials, etc.)
	Vaults map[string]vault.VaultDefinition `json:"vaults,omitempty"`

	// SecretsMap holds the new-format secrets: a flat map of name -> "vault:path" references.
	// Populated when the JSON "secrets" key contains a map[string]string (new format).
	SecretsMap map[string]string `json:"-"`

	// vaultManager orchestrates multi-vault secret resolution (nil when using old secrets path)
	vaultManager *vault.VaultManager `json:"-"`

	// Secrets configuration - single secrets provider (can be callback, aws, gcp, etc.)
	// Returns map[string]string stored in SecretsMap
	Secrets json.RawMessage `json:"secrets,omitempty"`
	secrets SecretsConfig   `json:"-"`

	// OnLoad callback executed during config initialization (global, not per-request)
	OnLoad callback.Callbacks `json:"on_load,omitempty"`

	// OnRequest callbacks executed after policies, before action (per-request)
	// Have access to modified request and store data in RequestData.Data
	OnRequest callback.Callbacks `json:"on_request,omitempty"`

	// OnResponse callbacks executed after the action handler responds (per-request).
	// Have access to the response status, headers, and size. Results are stored
	// in RequestData.Data.
	OnResponse callback.Callbacks `json:"on_response,omitempty"`

	// Params stores values returned from OnLoad callback
	// These are available to rules and other config components via RequestData.Config (immutable)
	Params map[string]any `json:"-"`

	// ParallelOnLoad enables concurrent execution of independent on_load callbacks.
	// When true, all on_load callbacks run in parallel instead of sequentially.
	ParallelOnLoad bool `json:"parallel_on_load,omitempty"`

	// onLoadLastExecuted tracks when on_load callback was last executed.
	// Uses atomic.Value to allow safe lock-free reads in the fast path
	// while writes happen under onLoadMu.
	onLoadLastExecuted atomic.Value `json:"-"` // stores time.Time

	// onLoadMu protects Params and onLoadReloading from concurrent access
	// during on_load cache reload.
	onLoadMu sync.Mutex `json:"-"`

	// onLoadReloading is true when a background reload is in progress.
	// Prevents duplicate background reloads.
	onLoadReloading bool `json:"-"`

	// ErrorPages defines custom error pages for specific status codes
	ErrorPages ErrorPages `json:"error_pages,omitempty"`

	// DefaultContentType is the fallback content type for error pages and system error responses
	DefaultContentType string `json:"default_content_type,omitempty" validate:"default_value=application/json"`

	// ProxyHeaders configures proxy header behavior (X-Forwarded-*, Via, security)
	// nil = use DefaultProxyHeaders (standard behavior)
	ProxyHeaders *ProxyHeaderConfig `json:"proxy_headers,omitempty"`

	// ProxyProtocol configures RFC-level proxy protocol behavior (TRACE blocking,
	// request smuggling protection, Max-Forwards, Date header)
	// nil = use DefaultProxyProtocol (secure defaults)
	ProxyProtocol *ProxyProtocolConfig `json:"proxy_protocol,omitempty"`

	// StreamingProxyConfig configures chunking, trailers, and flushing for the streaming proxy
	// nil = use DefaultStreamingConfig (auto-detect, 32KB chunks, trailers enabled)
	StreamingProxyConfig *StreamingProxyConfig `json:"streaming_proxy_config,omitempty"`

	// Compression configures proxy-level response compression (RFC 9110 Section 8.4)
	// nil = disabled (rely on upstream compression)
	Compression *CompressionConfig `json:"compression,omitempty"`

	// CORS configures Cross-Origin Resource Sharing headers
	// nil = disabled
	CORS *CORSConfig `json:"cors,omitempty"`

	// HSTS configures HTTP Strict Transport Security (RFC 6797)
	// nil = disabled
	HSTS *HSTSConfig `json:"hsts,omitempty"`

	// ProxyStatus configures RFC 9209 Proxy-Status header generation
	// nil = disabled
	ProxyStatus *ProxyStatusConfig `json:"proxy_status,omitempty"`

	// URINormalization configures request URI normalization (RFC 3986 Section 6)
	// nil = disabled (preserve original URI)
	URINormalization *URINormalizationConfig `json:"uri_normalization,omitempty"`

	// RateLimitHeaders configures standardized rate limit response headers
	// nil = disabled
	RateLimitHeaders *RateLimitHeaderConfig `json:"rate_limit_headers,omitempty"`

	// HTTPPriority configures HTTP Priority header handling (RFC 9218)
	// nil = disabled
	HTTPPriority *HTTPPriorityConfig `json:"http_priority,omitempty"`

	// ProblemDetails configures RFC 9457 error response format
	// nil = disabled
	ProblemDetails *ProblemDetailsConfig `json:"problem_details,omitempty"`

	// ClientHints configures HTTP Client Hints (RFC 8942)
	// nil = disabled
	ClientHints *ClientHintsConfig `json:"client_hints,omitempty"`

	// PriorityScheduler configures RFC 9218 priority-based response scheduling
	// nil = disabled
	PriorityScheduler *PrioritySchedulerConfig `json:"priority_scheduler,omitempty"`

	// TrafficCapture configures traffic exchange capture for this site/route.
	// The capture system uses the globally-configured messenger for real-time SSE streaming
	// and cacher (L2/L3) for buffered retention. No per-site storage config is needed.
	TrafficCapture *reqctx.TrafficCaptureConfig `json:"traffic_capture,omitempty"`

	// Events configures which event types to emit via the messenger.
	// Supports exact types ("ai.request.completed"), prefix wildcards ("ai.*"), or global ("*").
	Events []string `json:"events,omitempty"`

	// MessageSignatures configures RFC 9421 HTTP Message Signatures.
	// Supports signing outbound requests and verifying inbound request signatures.
	MessageSignatures *HTTPMessageSignatureConfig `json:"message_signatures,omitempty"`

	// APIVersioning configures API versioning with version extraction, deprecation headers,
	// and path rewriting. Enterprise: API versioning is an enterprise feature.
	APIVersioning json.RawMessage `json:"api_versioning,omitempty"`

	// ThreatProtection configures JSON/XML structural validation to prevent payload-based attacks.
	// nil = disabled
	ThreatProtection *ThreatProtectionConfig `json:"threat_protection,omitempty"`

	// BotDetection configures user-agent based bot detection with allow/deny lists,
	// optional reverse DNS verification, and configurable actions (block, challenge, log).
	// nil = disabled
	BotDetection *BotDetectionConfig `json:"bot_detection,omitempty"`

	// FallbackLoader loads a config for fallback origin resolution.
	// Set by the configloader to avoid import cycles (config ↔ configloader).
	FallbackLoader func(ctx context.Context, req *http.Request, fallback *FallbackOrigin) (*Config, error) `json:"-"`

	// OriginConfigLoader resolves an origin by hostname into its compiled http.Handler.
	// Used by MCP proxy handlers with origin_host to route through existing origins.
	// Set by the configloader to avoid import cycles (config ↔ configloader).
	OriginConfigLoader func(hostname string) (http.Handler, error) `json:"-"`

	// EmbeddedConfigLoader loads an embedded origin config and returns its compiled http.Handler.
	// Used by MCP proxy handlers with origin_config to route through inline origins.
	// Set by the configloader to avoid import cycles (config ↔ configloader).
	EmbeddedConfigLoader func(data []byte) (http.Handler, error) `json:"-"`

	ServerContextFn func(*http.Request) context.Context `json:"-"`

	// l3Cache is the L3 cache instance for caching error pages
	l3Cache cacher.Cacher `json:"-"`

	// envMap caches the per-origin env variables map built from config identity fields.
	// Computed once via envMapOnce; shared across requests (callers must not mutate).
	envMap     map[string]any `json:"-"`
	envMapOnce sync.Once      `json:"-"`

	// originCtx caches the OriginContext built from config identity + params + secrets.
	// Built once per config load, shared across requests.
	originCtx     *reqctx.OriginContext `json:"-"`
	originCtxOnce sync.Once             `json:"-"`
}

// Closeable is an optional interface that ActionConfig implementations can implement
// to clean up resources (e.g., stop background goroutines) when the config is replaced.
type Closeable interface {
	Close()
}

// Close releases resources held by this config. If the action implements Closeable,
// its Close method is called to stop background goroutines (e.g., health check probes).
// This should be called when a config is evicted from the cache or replaced during reload.
func (c *Config) Close() {
	if c == nil || c.action == nil {
		return
	}
	if closer, ok := c.action.(Closeable); ok {
		closer.Close()
	}
}

// maxParentDepth is the maximum number of parent configs to traverse.
// This prevents infinite loops from circular parent references.
const maxParentDepth = 20

// String returns a human-readable representation of the Config.
func (c *Config) String() string {
	var b strings.Builder
	c.writeStringChain(&b, 0)
	return b.String()
}

// writeStringChain is the depth-limited recursive helper for String().
func (c *Config) writeStringChain(b *strings.Builder, depth int) {
	if c.Parent != nil && depth < maxParentDepth {
		c.Parent.writeStringChain(b, depth+1)
		b.WriteString("\u2192") // → character
	}
	b.WriteString(c.ID)
}

// OriginChain returns a comma-separated "hostname/version" chain
// from root (first config loaded) to leaf (final config after forward rules).
// Used for the X-Sb-Origin debug header.
// Traversal is capped at maxParentDepth to prevent infinite loops.
func (c *Config) OriginChain() string {
	// Pre-calculate total length for single allocation
	totalLen := 0
	depth := 0
	for cur := c; cur != nil; cur = cur.Parent {
		if depth > maxParentDepth {
			break
		}
		totalLen += len(cur.Hostname) + 1 + len(cur.Version) // hostname + '/' + version
		depth++
	}
	if depth > 1 {
		totalLen += (depth - 1) * 2 // ", " separators
	}
	var b strings.Builder
	b.Grow(totalLen)
	c.writeChain(&b, 0)
	return b.String()
}

// EventEnabled checks whether this config should emit the given event type.
func (c *Config) EventEnabled(eventType string) bool {
	if c == nil || len(c.Events) == 0 {
		return false
	}
	for _, registered := range c.Events {
		if registered == "*" || registered == eventType {
			return true
		}
		if strings.HasSuffix(registered, ".*") {
			prefix := strings.TrimSuffix(registered, ".*")
			if strings.HasPrefix(eventType, prefix+".") {
				return true
			}
		}
	}
	return false
}

func (c *Config) writeChain(b *strings.Builder, depth int) {
	if c.Parent != nil && depth < maxParentDepth {
		c.Parent.writeChain(b, depth+1)
		b.WriteString(", ")
	}
	b.WriteString(c.Hostname)
	b.WriteByte('/')
	b.WriteString(c.Version)
}

// SetL3Cache sets the L3 cache instance for this config
func (c *Config) SetL3Cache(cache cacher.Cacher) {
	c.l3Cache = cache
}

// ClickHouseConfig holds connection settings for the ClickHouse HTTP API.
type ClickHouseConfig struct {
	Host     string
	Database string
}

// EnvMap returns the cached per-origin environment variables map.
// The map is built once from config identity fields and shared across requests.
// Callers must not mutate the returned map.
func (c *Config) EnvMap() map[string]any {
	c.envMapOnce.Do(func() {
		c.envMap = map[string]any{
			"workspace_id":  c.WorkspaceID,
			"origin_id":     c.ID,
			"hostname":      c.Hostname,
			"version":       c.Version,
			"revision":      c.Revision,
			"environment":   c.Environment,
			"origin_name":   c.OriginName,
			"config_mode":   c.ConfigMode,
			"config_reason": c.ConfigReason,
		}
		if len(c.Tags) > 0 {
			c.envMap["tags"] = c.Tags
		}
	})
	return c.envMap
}

// OriginCtx returns the cached OriginContext, building it on first call.
// The OriginContext is immutable and shared across requests for the same config.
func (c *Config) OriginCtx() *reqctx.OriginContext {
	c.originCtxOnce.Do(func() {
		c.originCtx = &reqctx.OriginContext{
			ID:           c.ID,
			Hostname:     c.Hostname,
			WorkspaceID:  c.WorkspaceID,
			Environment:  c.Environment,
			Version:      c.Version,
			Revision:     c.Revision,
			Name:         c.OriginName,
			Tags:         c.Tags,
			ConfigMode:   c.ConfigMode,
			ConfigReason: c.ConfigReason,
		}
	})
	return c.originCtx
}

// Validate checks that required fields are populated and returns a descriptive
// error listing all missing fields. Returns nil when the config is valid.
func (c *Config) Validate() error {
	var missing []string
	if c.ID == "" {
		missing = append(missing, "id")
	}
	if c.Hostname == "" {
		missing = append(missing, "hostname")
	}
	if c.WorkspaceID == "" {
		missing = append(missing, "workspace_id")
	}
	if len(missing) > 0 {
		return fmt.Errorf("config: required fields missing: %s", strings.Join(missing, ", "))
	}
	return nil
}

// GetVaultManager returns the vault manager, or nil if not configured.
func (c *Config) GetVaultManager() *vault.VaultManager {
	return c.vaultManager
}

// SetVaultManager sets the vault manager on the config.
func (c *Config) SetVaultManager(vm *vault.VaultManager) {
	c.vaultManager = vm
}
