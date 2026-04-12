// Package configloader loads and validates proxy configuration from the management API or local files.
//
// Config loading pipeline:
//  1. Host filter: bloom filter rejects unknown hostnames cheaply (avoids storage lookup).
//  2. Cache check: in-memory object cache with TTL (avoids repeated storage/API calls).
//  3. Storage/API lookup: fetch config from database, PebbleDB, or REST API.
//  4. Workspace access check: reject requests for wrong/drained workspaces.
//  5. Enrichment: populate RequestData with params, secrets, env, variables, feature flags.
//  6. Failsafe: if active config fails, serve the last-known-good snapshot.
package configloader

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/object"
	"github.com/soapbucket/sbproxy/internal/config"
	"github.com/soapbucket/sbproxy/internal/loader/featureflags"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/observe/events"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/platform/servervar"
	"github.com/soapbucket/sbproxy/internal/platform/storage"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/request/session"
	"github.com/soapbucket/sbproxy/internal/security/crypto"
	"github.com/soapbucket/sbproxy/internal/vault"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

// DefaultMaxForwardDepth is the default value for max forward depth.
const DefaultMaxForwardDepth = 10

const (
	configModeActive   = "active"
	configModeFailsafe = "failsafe"

	configReasonSourceUnavailable   = "source_unavailable"
	configReasonValidationFailed    = "validation_failed"
	configReasonLoadFailed          = "load_failed"
	configReasonWildcardFallback    = "wildcard_fallback"
	configReasonExplicitFailsafe    = "explicit_failsafe"
	configReasonSnapshotCorrupt     = "active_snapshot_corrupt"
	configReasonSnapshotUnavailable = "active_snapshot_missing"
)

// ErrMaxForwardDepthReached is a sentinel error for max forward depth reached conditions.
var ErrMaxForwardDepthReached = errors.New("max forward depth reached")

// ErrMaxFallbackDepthReached is a sentinel error for max fallback depth reached conditions.
var ErrMaxFallbackDepthReached = errors.New("max fallback depth reached")

// ErrNotFound is a sentinel error for not found conditions.
var ErrNotFound = errors.New("config not found")

// ErrInvalidProxyKey is a sentinel error for invalid proxy key conditions.
var ErrInvalidProxyKey = errors.New("invalid proxy API key")

// ProxyKeyValidationResult holds the validated key info for tracking
type ProxyKeyValidationResult struct {
	Config       *config.Config
	WorkspaceID  string
	ProxyKeyID   string // UUID of the ProxyAPIKey that authenticated
	ProxyKeyName string // Name of the key (e.g., "production")
}

// ProxyAuthResult is the authenticated proxy client context used by the HTTPS proxy runtime.
type ProxyAuthResult struct {
	OriginID     string
	WorkspaceID  string
	ProxyKeyID   string
	ProxyKeyName string
	ProxyConfig  *config.Config
}

// ErrFallbackCycle is a sentinel error for circular fallback detection.
var ErrFallbackCycle = errors.New("circular fallback detected")

type fallbackDepthKey struct{}
type explicitFailsafeDepthKey struct{}
type fallbackVisitedKey struct{}

// GetFallbackDepth returns the current fallback depth from the context.
func GetFallbackDepth(ctx context.Context) int {
	if depth, ok := ctx.Value(fallbackDepthKey{}).(int); ok {
		return depth
	}
	return 0
}

// WithFallbackDepth returns a new context with the specified fallback depth.
func WithFallbackDepth(ctx context.Context, depth int) context.Context {
	return context.WithValue(ctx, fallbackDepthKey{}, depth)
}

func getExplicitFailsafeDepth(ctx context.Context) int {
	if depth, ok := ctx.Value(explicitFailsafeDepthKey{}).(int); ok {
		return depth
	}
	return 0
}

func withExplicitFailsafeDepth(ctx context.Context, depth int) context.Context {
	return context.WithValue(ctx, explicitFailsafeDepthKey{}, depth)
}

// getFallbackVisited returns the set of hostnames already visited in the fallback chain.
func getFallbackVisited(ctx context.Context) map[string]bool {
	if visited, ok := ctx.Value(fallbackVisitedKey{}).(map[string]bool); ok {
		return visited
	}
	return nil
}

// withFallbackVisited returns a new context with the given visited set.
func withFallbackVisited(ctx context.Context, visited map[string]bool) context.Context {
	return context.WithValue(ctx, fallbackVisitedKey{}, visited)
}

// loadFallbackConfig loads a config by hostname for fallback purposes.
// It uses a separate depth counter from forward rules to prevent infinite loops
// and a visited set to detect circular fallback chains.
func (l *Loader) loadFallbackConfig(ctx context.Context, req *http.Request, fallback *config.FallbackOrigin, m manager.Manager, parent *config.Config) (*config.Config, error) {
	if fallback == nil {
		return nil, fmt.Errorf("fallback config is nil")
	}

	currentDepth := GetFallbackDepth(ctx)
	maxDepth := getMaxOriginRecursionDepth(m)
	if currentDepth >= maxDepth {
		return nil, ErrMaxFallbackDepthReached
	}

	// Circular fallback detection: track visited hostnames to produce
	// a descriptive error when the same origin appears twice in the chain.
	visited := getFallbackVisited(ctx)
	if visited == nil {
		visited = make(map[string]bool, 4)
	}
	target := fallback.Hostname
	if target == "" {
		target = "__embedded__"
	}
	if visited[target] {
		return nil, fmt.Errorf("%w: %s already visited in fallback chain", ErrFallbackCycle, target)
	}
	// Copy-on-write so sibling branches do not interfere with each other.
	next := make(map[string]bool, len(visited)+1)
	for k, v := range visited {
		next[k] = v
	}
	next[target] = true

	ctx = WithFallbackDepth(ctx, currentDepth+1)
	ctx = withFallbackVisited(ctx, next)
	// Update request context so downstream calls see the new depth
	req = req.WithContext(ctx)

	// Embedded fallback config resolution takes precedence when configured.
	if fallback.HasEmbeddedOrigin() {
		cfg, err := l.loadEmbeddedConfig(fallback.Origin, parent, m)
		if err != nil {
			return nil, fmt.Errorf("failed to load embedded fallback config: %w", err)
		}
		return cfg, nil
	}

	cfg, err := l.getConfigByHostname(ctx, req, fallback.Hostname, 0, m, parent)
	if err != nil {
		return nil, fmt.Errorf("failed to load fallback config %q: %w", fallback.Hostname, err)
	}

	return cfg, nil
}

// LoadFallbackConfig is the package-level compatibility wrapper.
//
// Deprecated: Use Loader.loadFallbackConfig() instead.
func LoadFallbackConfig(ctx context.Context, req *http.Request, fallback *config.FallbackOrigin, m manager.Manager, parent *config.Config) (*config.Config, error) {
	return defaultLoader.loadFallbackConfig(ctx, req, fallback, m, parent)
}

// HostChecker is the interface for bloom filter hostname pre-checking.
type HostChecker interface {
	Check(hostname string) bool
}

// Loader holds all configloader state and dependencies. The host filter provides
// bloom-filter-based pre-checking to reject unknown hostnames before touching
// storage. The drainedWorkspaces map tracks workspaces being migrated off this
// instance (operator-controlled via internal API).
type Loader struct {
	cache                *objectcache.ObjectCache
	hostFilter           HostChecker
	dedicatedWorkspaceID string
	drainedWorkspaces    sync.Map
	failsafeSnapshots    *failsafeSnapshotStore
}

// Option configures a Loader.
type Option func(*Loader)

// WithHostFilter sets the bloom filter for hostname pre-checking.
func WithHostFilter(hf HostChecker) Option {
	return func(l *Loader) {
		l.hostFilter = hf
	}
}

// WithWorkspaceID restricts this loader to serving a single workspace.
func WithWorkspaceID(id string) Option {
	return func(l *Loader) {
		l.dedicatedWorkspaceID = id
	}
}

// NewLoader creates a Loader with the given options. If no options are provided,
// the loader uses sensible defaults (10-minute cache TTL, 1000 max entries).
func NewLoader(opts ...Option) *Loader {
	c, _ := objectcache.NewObjectCache(10*time.Minute, 1*time.Minute, 1000, 100*1024*1024)
	l := &Loader{
		cache:             c,
		failsafeSnapshots: newFailsafeSnapshotStore(),
	}
	for _, opt := range opts {
		opt(l)
	}
	return l
}

// defaultLoader is the package-level singleton used by all compatibility wrappers.
var defaultLoader = NewLoader()

// DefaultLoader returns the package-level Loader singleton. This is useful for
// passing the loader as a dependency to other components (e.g., OriginHandler).
func DefaultLoader() *Loader {
	return defaultLoader
}

// LoaderOptions bundles the configloader's dependencies for testability.
// Use Configure() to set all options at once, or the individual Set* functions.
//
// Deprecated: Use NewLoader with functional options instead.
type LoaderOptions struct {
	HostFilter  HostChecker
	WorkspaceID string
}

// Configure sets all loader options from the given struct.
// Zero values are treated as "not set" (existing values are cleared).
//
// Deprecated: Use NewLoader with functional options instead.
func Configure(opts LoaderOptions) {
	defaultLoader.hostFilter = opts.HostFilter
	defaultLoader.dedicatedWorkspaceID = opts.WorkspaceID
}

// SetHostFilter sets the bloom filter for hostname pre-checking.
func (l *Loader) SetHostFilter(hf HostChecker) {
	l.hostFilter = hf
}

// SetWorkspaceID configures the loader to serve only one workspace.
func (l *Loader) SetWorkspaceID(id string) {
	l.dedicatedWorkspaceID = id
}

// SetHostFilter sets the bloom filter for hostname pre-checking on the default loader.
//
// Deprecated: Use Loader.SetHostFilter() instead.
func SetHostFilter(hf HostChecker) {
	defaultLoader.SetHostFilter(hf)
}

// SetWorkspaceID configures the default loader to serve only one workspace.
//
// Deprecated: Use Loader.SetWorkspaceID() instead.
func SetWorkspaceID(id string) {
	defaultLoader.SetWorkspaceID(id)
}

// cacheConfig stores a config in the cache, closing any previous config for the same key
// to release resources like health check goroutines.
func (l *Loader) cacheConfig(key string, cfg *config.Config) {
	if old, ok := l.cache.Get(key); ok {
		if oldCfg, ok := old.(*config.Config); ok {
			oldCfg.Close()
		}
	}
	l.cache.Put(key, cfg)
}

// normalizeHost strips the port from a host:port string.
func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil && h != "" {
		return h
	}
	return host
}

// checkHostFilter returns a disabled config if the hostname is rejected by the bloom filter.
// Returns nil if the host passes or no filter is configured.
func (l *Loader) checkHostFilter(hostname, normalizedHost string) *config.Config {
	if l.hostFilter == nil || normalizedHost == "" {
		return nil
	}
	if !l.hostFilter.Check(normalizedHost) {
		slog.Debug("host filter rejected hostname", "hostname", normalizedHost)
		metric.HostFilterRejection(normalizedHost)
		return &config.Config{
			Hostname: hostname,
			ID:       "host-filtered",
			Disabled: true,
		}
	}
	metric.HostFilterPass()
	return nil
}

// checkWorkspaceAccess returns a disabled config if the workspace is filtered or drained.
// Returns nil if access is allowed.
func (l *Loader) checkWorkspaceAccess(hostname string, cfg *config.Config) *config.Config {
	// In dedicated mode, reject configs that belong to a different workspace
	if l.dedicatedWorkspaceID != "" && cfg.WorkspaceID != "" && cfg.WorkspaceID != l.dedicatedWorkspaceID {
		slog.Debug("rejecting request for different workspace in dedicated mode",
			"request_workspace", cfg.WorkspaceID,
			"dedicated_workspace", l.dedicatedWorkspaceID,
			"hostname", hostname)
		return &config.Config{
			Hostname: hostname,
			ID:       "workspace-filtered",
			Disabled: true,
		}
	}

	// Check if this workspace is being drained from this instance
	if cfg.WorkspaceID != "" {
		if _, draining := l.drainedWorkspaces.Load(cfg.WorkspaceID); draining {
			slog.Debug("rejecting request for drained workspace",
				"workspace_id", cfg.WorkspaceID,
				"hostname", hostname)
			return &config.Config{
				Hostname: hostname,
				ID:       "workspace-draining",
				Disabled: true,
			}
		}
	}

	return nil
}

// populateSecrets loads secrets from vault or legacy provider into the request data.
func populateSecrets(ctx context.Context, cfg *config.Config, rd *reqctx.RequestData) {
	if vm := cfg.GetVaultManager(); vm != nil {
		vaultSecrets := vm.GetAllSecrets()
		if len(vaultSecrets) > 0 {
			rd.Secrets = vaultSecrets
			slog.Debug("stored vault secrets in request context",
				"origin_id", cfg.ID, "hostname", cfg.Hostname,
				"secret_count", len(vaultSecrets))
		}
	} else {
		secrets := cfg.GetSecrets(ctx)
		if len(secrets) > 0 {
			rd.Secrets = secrets
			slog.Debug("stored secrets in request context",
				"origin_id", cfg.ID, "hostname", cfg.Hostname,
				"secret_count", len(secrets))
		} else {
			if len(cfg.Secrets) > 0 {
				slog.Warn("secrets configured but not loaded",
					"origin_id", cfg.ID, "hostname", cfg.Hostname,
					"secrets_len", len(cfg.Secrets))
			}
			slog.Debug("no secrets to store in request context",
				"origin_id", cfg.ID, "hostname", cfg.Hostname)
		}
	}
}

// enrichRequestData populates the RequestData with config params, secrets, env,
// variables, feature flags, and the V2 context model.
func (l *Loader) enrichRequestData(ctx context.Context, cfg *config.Config, rd *reqctx.RequestData, req *http.Request, m manager.Manager) {
	// Set fallback loader to avoid import cycle (config -> configloader)
	if cfg.FallbackOrigin != nil {
		cfg.FallbackLoader = func(ctx context.Context, req *http.Request, fallback *config.FallbackOrigin) (*config.Config, error) {
			return l.loadFallbackConfig(ctx, req, fallback, m, cfg)
		}
	}

	// Get params (reloads on_load callback if needed based on CacheDuration)
	params := cfg.GetConfigParams(ctx)
	rd.Config = params

	populateSecrets(ctx, cfg, rd)

	// Share the cached per-origin env variables (built once per config)
	rd.Env = cfg.EnvMap()

	// Propagate config-level variables to request context
	if len(cfg.Variables) > 0 {
		rd.Variables = cfg.Variables
	}

	// Populate feature flags from the global manager (workspace-scoped, real-time)
	if wsID := cfg.WorkspaceID; wsID != "" {
		ffMgr := featureflags.GetGlobalManager()
		if flags := ffMgr.GetFlags(ctx, wsID); len(flags) > 0 {
			rd.FeatureFlags = flags
		}
	}

	// Populate bridge fields for new context model (V2 migration)
	enrichWithNewContext(cfg, rd, req)

	if len(params) > 0 {
		slog.Debug("stored config params in request context",
			"origin_id", cfg.ID, "hostname", cfg.Hostname,
			"param_count", len(params))
	}
}

// LoadConfig performs the load operation on the Loader instance.
func (l *Loader) LoadConfig(req *http.Request, m manager.Manager) (*config.Config, error) {
	slog.Debug("loading origin config", "hostname", req.Host, "path", req.URL.Path)

	normalizedHost := normalizeHost(req.Host)

	if rejected := l.checkHostFilter(req.Host, normalizedHost); rejected != nil {
		return rejected, nil
	}

	cfg, err := l.getConfigByHostname(req.Context(), req, req.Host, 0, m, nil)
	if err != nil {
		return nil, err
	}

	if rejected := l.checkWorkspaceAccess(req.Host, cfg); rejected != nil {
		return rejected, nil
	}

	ctx := req.Context()
	requestData := reqctx.GetRequestData(ctx)
	if requestData == nil {
		requestData = reqctx.NewRequestData()
	}

	l.enrichRequestData(ctx, cfg, requestData, req, m)

	*req = *req.WithContext(reqctx.SetRequestData(ctx, requestData))

	return cfg, nil
}

// LoadCompiledOrigin is the compile-on-demand path: loads the raw config from
// storage, compiles it into a CompiledOrigin, and returns it for caching.
// Returns (nil, nil) if the config is not found or disabled.
func (l *Loader) LoadCompiledOrigin(req *http.Request, m manager.Manager, services plugin.ServiceProvider) (*config.CompiledOrigin, error) {
	cfg, err := l.LoadConfig(req, m)
	if err != nil {
		return nil, err
	}
	if cfg == nil || cfg.Disabled {
		return nil, nil
	}

	raw := configToRawOrigin(cfg)
	compiled, err := config.CompileOrigin(raw, services)
	if err != nil {
		return nil, fmt.Errorf("compile origin %q: %w", cfg.Hostname, err)
	}

	return compiled, nil
}

// configToRawOrigin converts a loaded Config into a RawOrigin suitable for
// compilation. Fields that are already json.RawMessage on Config (Action, Auth,
// Policies, Transforms, Secrets) are copied directly. Typed struct fields are
// marshaled back to JSON.
func configToRawOrigin(cfg *config.Config) *config.RawOrigin {
	raw := &config.RawOrigin{
		ID:             cfg.ID,
		Hostname:       cfg.Hostname,
		WorkspaceID:    cfg.WorkspaceID,
		Version:        cfg.Version,
		Disabled:       cfg.Disabled,
		ForceSSL:       cfg.ForceSSL,
		Debug:          cfg.Debug,
		AllowedMethods: cfg.AllowedMethods,
		Variables:      cfg.Variables,

		// These are already json.RawMessage on Config.
		Action:     cfg.Action,
		Auth:       cfg.Auth,
		Policies:   cfg.Policies,
		Transforms: cfg.Transforms,
		Secrets:    cfg.Secrets,
	}

	// Marshal typed struct fields to json.RawMessage for the compiler.
	raw.Modifiers = marshalOrNil(cfg.RequestModifiers)
	raw.ResponseModifiers = marshalOrNil(cfg.ResponseModifiers)
	raw.Cache = marshalOrNil(cfg.ResponseCache)
	raw.OnLoad = marshalOrNil(cfg.OnLoad)
	raw.OnRequest = marshalOrNil(cfg.OnRequest)
	raw.OnResponse = marshalOrNil(cfg.OnResponse)
	raw.Compression = marshalOrNil(cfg.Compression)
	raw.CORS = marshalOrNil(cfg.CORS)
	raw.HSTS = marshalOrNil(cfg.HSTS)
	raw.Events = marshalOrNil(cfg.Events)
	raw.ErrorPages = marshalOrNil(cfg.ErrorPages)
	raw.MessageSignatures = marshalOrNil(cfg.MessageSignatures)
	raw.BotDetection = marshalOrNil(cfg.BotDetection)
	raw.ThreatProtection = marshalOrNil(cfg.ThreatProtection)
	raw.Session = marshalOrNil(cfg.SessionConfig)
	raw.TrafficCapture = marshalOrNil(cfg.TrafficCapture)
	raw.RateLimitHeaders = marshalOrNil(cfg.RateLimitHeaders)

	return raw
}

// marshalOrNil marshals v to JSON. Returns nil if v is nil or marshaling fails.
func marshalOrNil(v any) json.RawMessage {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	// Don't return "null" as a raw message.
	if string(b) == "null" {
		return nil
	}
	return b
}

// Load is the package-level compatibility wrapper.
//
// Deprecated: Use Loader.LoadConfig() instead.
func Load(req *http.Request, m manager.Manager) (*config.Config, error) {
	return defaultLoader.LoadConfig(req, m)
}

// enrichWithNewContext populates the V2 bridge fields on RequestData.
// This runs alongside the existing field population so both old and new code paths work.
func enrichWithNewContext(cfg *config.Config, rd *reqctx.RequestData, req *http.Request) {
	// OriginContext - built once per config, shallow-copied per request to avoid races
	shared := cfg.OriginCtx()
	originCtx := *shared // shallow copy so concurrent requests don't mutate the shared instance
	originCtx.Params = rd.Config
	if len(rd.Secrets) > 0 {
		originCtx.Secrets = rd.Secrets
	}
	rd.OriginCtx = &originCtx

	// ServerContext - global singleton
	rd.ServerCtx = servervar.GetServerContext()

	// VarsContext - per-origin config variables
	if len(cfg.Variables) > 0 {
		rd.VarsCtx = &reqctx.VarsContext{Data: cfg.Variables}
	}

	// FeaturesContext - from feature flags already loaded
	if len(rd.FeatureFlags) > 0 {
		rd.FeaturesCtx = &reqctx.FeaturesContext{Data: rd.FeatureFlags}
	}

	// RequestSnapshot - built from original request
	if rd.OriginalRequest != nil {
		rd.Snapshot = reqctx.BuildRequestSnapshot(rd.OriginalRequest)
	}

	// SessionContext - built from session data
	if rd.SessionData != nil {
		rd.SessionCtx = reqctx.BuildSessionContext(rd.SessionData)
	}

	// ClientContext - built from enrichment data
	remoteAddr := ""
	if req != nil {
		remoteAddr = req.RemoteAddr
		if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			remoteAddr = host
		}
	}
	rd.ClientCtx = reqctx.BuildClientContext(remoteAddr, rd.Location, rd.UserAgent, rd.Fingerprint)
}

// authenticateProxyClient validates proxy credentials and returns workspace-scoped auth context.
func (l *Loader) authenticateProxyClient(ctx context.Context, originID string, apiKey string, m manager.Manager) (*ProxyAuthResult, error) {
	slog.Debug("loading origin config by ID for proxy auth", "origin_id", originID)

	// Load origin config from storage by ID (not hostname)
	data, err := m.GetStorage().GetByID(ctx, originID)
	if err != nil {
		if errors.Is(err, storage.ErrKeyNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if data == nil {
		return nil, ErrNotFound
	}

	// Parse config JSON
	cfg, err := config.Load(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate API key against all active keys for this origin
	// Call storage to validate the key
	validKeyResult, err := m.GetStorage().ValidateProxyAPIKey(ctx, originID, apiKey)
	if err != nil {
		slog.Warn("proxy API key validation failed", "origin_id", originID, "error", err)
		return nil, ErrInvalidProxyKey
	}

	slog.Info("proxy API key verified", "origin_id", originID, "key_name", validKeyResult.ProxyKeyName)

	// Cache the result (separate namespace from hostname cache)
	// Include workspace ID in cache key for tenant isolation
	cacheKey := fmt.Sprintf("proxy:%s:%s", cfg.WorkspaceID, originID)
	l.cacheConfig(cacheKey, cfg)

	// Set L3 cache if available
	if l3Cache := m.GetCache(manager.L3Cache); l3Cache != nil {
		cfg.SetL3Cache(l3Cache)
	}

	l.configureLoadedConfig(cfg, m)

	return &ProxyAuthResult{
		OriginID:     originID,
		WorkspaceID:  cfg.WorkspaceID,
		ProxyConfig:  cfg,
		ProxyKeyID:   validKeyResult.ProxyKeyID,
		ProxyKeyName: validKeyResult.ProxyKeyName,
	}, nil
}

// AuthenticateProxyClient is the package-level compatibility wrapper.
func AuthenticateProxyClient(ctx context.Context, originID string, apiKey string, m manager.Manager) (*ProxyAuthResult, error) {
	return defaultLoader.authenticateProxyClient(ctx, originID, apiKey, m)
}

// LoadByOriginID loads origin config by ID and validates API key for proxy authentication.
// Deprecated for new HTTPS proxy runtime code. Prefer AuthenticateProxyClient.
func LoadByOriginID(ctx context.Context, originID string, apiKey string, m manager.Manager) (*ProxyKeyValidationResult, error) {
	result, err := AuthenticateProxyClient(ctx, originID, apiKey, m)
	if err != nil {
		return nil, err
	}
	return &ProxyKeyValidationResult{
		Config:       result.ProxyConfig,
		WorkspaceID:  result.WorkspaceID,
		ProxyKeyID:   result.ProxyKeyID,
		ProxyKeyName: result.ProxyKeyName,
	}, nil
}

// loadForProxyHost resolves a managed config for a CONNECT target hostname within the
// authenticated proxy client's workspace. It returns ErrNotFound for unmanaged hosts.
func (l *Loader) loadForProxyHost(ctx context.Context, auth *ProxyAuthResult, hostname string, m manager.Manager) (*config.Config, error) {
	if auth == nil {
		return nil, fmt.Errorf("proxy auth context is required")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+hostname+"/", nil)
	if err != nil {
		return nil, err
	}
	req.Host = hostname

	return l.loadForProxyRequest(req, auth.WorkspaceID, m)
}

// loadForProxyRequest resolves a managed config for an intercepted request and ensures it
// belongs to the authenticated workspace. It returns ErrNotFound for unmanaged hosts.
func (l *Loader) loadForProxyRequest(req *http.Request, workspaceID string, m manager.Manager) (*config.Config, error) {
	cfg, err := l.LoadConfig(req, m)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if cfg == nil || cfg.Disabled {
		return nil, ErrNotFound
	}
	if workspaceID != "" && cfg.WorkspaceID != "" && cfg.WorkspaceID != workspaceID {
		return nil, ErrNotFound
	}
	return cfg, nil
}

// LoadForProxyHost is the package-level compatibility wrapper.
func LoadForProxyHost(ctx context.Context, auth *ProxyAuthResult, hostname string, m manager.Manager) (*config.Config, error) {
	return defaultLoader.loadForProxyHost(ctx, auth, hostname, m)
}

// LoadForProxyRequest is the package-level compatibility wrapper.
func LoadForProxyRequest(req *http.Request, workspaceID string, m manager.Manager) (*config.Config, error) {
	return defaultLoader.loadForProxyRequest(req, workspaceID, m)
}

// loadConfigByID loads a config by origin ID for internal routing purposes without validating
// proxy credentials. Callers must enforce their own authorization rules before using it.
func (l *Loader) loadConfigByID(ctx context.Context, originID string, m manager.Manager) (*config.Config, error) {
	data, err := m.GetStorage().GetByID(ctx, originID)
	if err != nil {
		if errors.Is(err, storage.ErrKeyNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if data == nil {
		return nil, ErrNotFound
	}

	cfg, err := config.Load(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	l.configureLoadedConfig(cfg, m)
	return cfg, nil
}

// LoadConfigByID is the package-level compatibility wrapper.
func LoadConfigByID(ctx context.Context, originID string, m manager.Manager) (*config.Config, error) {
	return defaultLoader.loadConfigByID(ctx, originID, m)
}

// tryFailsafeResolution attempts to load a failsafe config (snapshot or explicit).
// Returns the failsafe config if successful, or nil if no failsafe is available.
func (l *Loader) tryFailsafeResolution(ctx context.Context, hostname string, parent *config.Config, m manager.Manager, eventType, reason, detail string) *config.Config {
	if failsafeCfg, err := l.loadFailsafeSnapshotConfig(ctx, hostname, parent, m, reason, detail); err == nil {
		emitConfigEvent(ctx, failsafeCfg, eventType, events.SeverityError, "load", reason, detail, "")
		emitConfigEvent(ctx, failsafeCfg, "config.failsafe_served", events.SeverityWarning, "serve", reason, detail, "exact_lkg")
		return failsafeCfg
	}
	if explicitCfg, err := l.loadExplicitFailsafeOriginConfig(ctx, hostname, parent, m); err == nil {
		emitConfigEvent(ctx, explicitCfg, eventType, events.SeverityError, "load", reason, detail, "")
		emitConfigEvent(ctx, explicitCfg, "config.failsafe_served", events.SeverityWarning, "serve", configReasonExplicitFailsafe, detail, "explicit_failsafe")
		return explicitCfg
	}
	return nil
}

// applyForwardRules checks if any forward rule matches the request and recursively
// loads the target config. Returns nil if no forward rule matched.
func (l *Loader) applyForwardRules(ctx context.Context, req *http.Request, cfg *config.Config, hostname string, depth int, m manager.Manager, label string) (*config.Config, error) {
	if len(cfg.ForwardRules) == 0 {
		return nil, nil
	}
	slog.Debug("checking forward rules"+label, "hostname", hostname, "path", req.URL.Path, "forward_rules_count", len(cfg.ForwardRules))
	matched := cfg.ForwardRules.ApplyRule(req)
	if matched == nil {
		slog.Debug("no forward rule matched"+label, "hostname", hostname, "path", req.URL.Path)
		return nil, nil
	}
	if matched.Hostname != "" {
		slog.Debug("dynamic forward matched"+label, "from", hostname, "to", matched.Hostname, "path", req.URL.Path)
		return l.getConfigByHostname(ctx, req, matched.Hostname, depth+1, m, cfg)
	}
	if len(matched.Origin) > 0 {
		slog.Debug("dynamic embedded forward matched"+label, "from", hostname, "path", req.URL.Path)
		return loadEmbeddedConfig(matched.Origin, cfg, m)
	}
	return nil, nil
}

// getConfigByHostname loads config by hostname with forward depth tracking
func (l *Loader) getConfigByHostname(ctx context.Context, req *http.Request, hostname string, depth int, m manager.Manager, parent *config.Config) (*config.Config, error) {
	// Check max forward depth
	maxDepth := getMaxOriginRecursionDepth(m)
	if depth > maxDepth {
		return nil, ErrMaxForwardDepthReached
	}

	var cfg *config.Config

	// Build cache key: use workspace:id:hostname format when workspace is available
	// Otherwise use just hostname for backward compatibility and testing
	var cacheKey string

	entry, ok := l.cache.Get(hostname)
	if ok {

		cfg = entry.(*config.Config)

		// Set L3 cache on cached config (in case it wasn't set before)
		if l3Cache := m.GetCache(manager.L3Cache); l3Cache != nil {
			cfg.SetL3Cache(l3Cache)
		}

		if fwdCfg, fwdErr := l.applyForwardRules(ctx, req, cfg, hostname, depth, m, " (cached)"); fwdCfg != nil || fwdErr != nil {
			return fwdCfg, fwdErr
		}

		// Check must_match_rules before returning cached config
		if !checkMustMatchRules(cfg, req) {
			slog.Debug("request does not match must_match_rules, skipping origin",
				"config_id", cfg.ID,
				"hostname", hostname,
				"path", req.URL.Path,
				"method", req.Method)
			metric.RequestRuleRejection(cfg.ID)
			return &config.Config{
				Hostname: hostname,
				ID:       "rules-not-matched",
				Disabled: true,
			}, nil
		}

		// Config is cached - return it
		// Note: on_load callback should have already run when config was first loaded,
		// so cfg.Params should be populated. If it's empty, on_load may have failed or not run.
		// If CacheDuration is set, on_load will be reloaded when expired.
		return cfg, nil
	}

	// Load from storage
	data, err := m.GetStorage().Get(ctx, hostname)
	if err != nil && !errors.Is(err, storage.ErrKeyNotFound) {
		metric.ConfigReload(hostname, "failure")
		metric.ConfigError(hostname, "storage_error")
		if fs := l.tryFailsafeResolution(ctx, hostname, parent, m, "config.source_unavailable", configReasonSourceUnavailable, err.Error()); fs != nil {
			return fs, nil
		}
		return nil, err
	}

	if data == nil {
		slog.Debug("config not found for hostname", "hostname", hostname)

		if fs := l.tryFailsafeResolution(ctx, hostname, parent, m, "config.not_found", configReasonLoadFailed, "hostname not in storage"); fs != nil {
			return fs, nil
		}

		// Try hostname fallback if enabled and hostname contains a port
		if m.GetGlobalSettings().OriginLoaderSettings.HostnameFallback {

			if hostnameWithoutPort, _, _ := net.SplitHostPort(hostname); hostnameWithoutPort != hostname && hostnameWithoutPort != "" {
				slog.Debug("trying hostname fallback", "original", hostname, "fallback", hostnameWithoutPort)
				return l.getConfigByHostname(ctx, req, hostnameWithoutPort, depth, m, parent)
			}
		}

		// Try wildcard hostname fallback (single-level only)
		// e.g., "api.example.com" -> "*.example.com"
		dotIdx := strings.IndexByte(hostname, '.')
		if dotIdx > 0 && dotIdx < len(hostname)-1 {
			wildcardHostname := "*" + hostname[dotIdx:]
			slog.Debug("trying wildcard hostname fallback", "original", hostname, "wildcard", wildcardHostname)
			wildcardData, wildcardErr := m.GetStorage().Get(ctx, wildcardHostname)
			if wildcardErr == nil && wildcardData != nil {
				wildcardCfg, parseErr := config.Load(wildcardData)
				if parseErr != nil {
					slog.Error("failed to parse wildcard config", "hostname", wildcardHostname, "error", parseErr)
					if failsafeCfg, err := l.loadFailsafeSnapshotConfig(ctx, wildcardHostname, parent, m, configReasonWildcardFallback, parseErr.Error()); err == nil {
						failsafeCfg.ConfigReason = configReasonWildcardFallback
						emitConfigEvent(ctx, failsafeCfg, "config.validation_failed", events.SeverityError, "validate", classifyFailureReason(parseErr), parseErr.Error(), "")
						emitConfigEvent(ctx, failsafeCfg, "config.failsafe_served", events.SeverityWarning, "serve", configReasonWildcardFallback, "serving wildcard last-known-good snapshot", "wildcard_lkg")
						return failsafeCfg, nil
					}
					if explicitCfg, explicitErr := l.loadExplicitFailsafeOriginConfig(ctx, wildcardHostname, parent, m); explicitErr == nil {
						explicitCfg.ConfigReason = configReasonExplicitFailsafe
						emitConfigEvent(ctx, explicitCfg, "config.validation_failed", events.SeverityError, "validate", classifyFailureReason(parseErr), parseErr.Error(), "")
						emitConfigEvent(ctx, explicitCfg, "config.failsafe_served", events.SeverityWarning, "serve", configReasonExplicitFailsafe, "serving configured wildcard failsafe origin", "explicit_failsafe")
						return explicitCfg, nil
					}
				} else {
					// Cross-tenant validation: check if wildcard matches expected workspace
					// If we have a parent config, verify wildcard is in same workspace
					if parent != nil && parent.WorkspaceID != "" && wildcardCfg.WorkspaceID != parent.WorkspaceID {
						slog.Warn("wildcard workspace mismatch", "wildcard_ws", wildcardCfg.WorkspaceID, "parent_ws", parent.WorkspaceID, "wildcard", wildcardHostname)
						return nil, ErrNotFound
					}

					wildcardCfg.Parent = parent
					ensureConfigID(wildcardCfg, hostname)
					wildcardCfg.ConfigMode = configModeActive
					wildcardCfg.ConfigReason = configReasonWildcardFallback
					l.configureLoadedConfig(wildcardCfg, m)
					l.saveFailsafeSnapshot(wildcardHostname, wildcardCfg, wildcardData)
					// Cache with workspace partition (use hostname as key if no workspace)
					l.cacheConfig(hostname, wildcardCfg)
					metric.ConfigReload(hostname, "success")
					return wildcardCfg, nil
				}
			}
		}

		cfg := &config.Config{
			Hostname: hostname,
			ID:       "null-config",
			Disabled: true,
		}

		// Set L3 cache on null config
		if l3Cache := m.GetCache(manager.L3Cache); l3Cache != nil {
			cfg.SetL3Cache(l3Cache)
		}

		// Cache null config (no workspace context for non-existent configs)
		l.cacheConfig(hostname, cfg)
		// Record config reload success (null config is still a successful load)
		metric.ConfigReload(hostname, "success")
		return cfg, nil
	}

	cfg, err = config.Load(data)
	if err != nil {
		// Record config reload failure
		metric.ConfigReload(hostname, "failure")
		// Determine error type
		errorType := "parse_error"
		if errStr := err.Error(); errStr != "" {
			if strings.Contains(errStr, "secrets") {
				errorType = "secrets_error"
			} else if strings.Contains(errStr, "unmarshal") {
				errorType = "parse_error"
			} else if strings.Contains(errStr, "validation") {
				errorType = "validation_error"
			}
		}
		metric.ConfigError(hostname, errorType)
		if failsafeCfg, fallbackErr := l.loadFailsafeSnapshotConfig(ctx, hostname, parent, m, classifyFailureReason(err), err.Error()); fallbackErr == nil {
			eventType := "config.validation_failed"
			if strings.Contains(strings.ToLower(err.Error()), "compile") || strings.Contains(strings.ToLower(err.Error()), "lua") || strings.Contains(strings.ToLower(err.Error()), "cel") {
				eventType = "config.compile_failed"
			}
			emitConfigEvent(ctx, failsafeCfg, eventType, events.SeverityError, "validate", classifyFailureReason(err), err.Error(), "")
			emitConfigEvent(ctx, failsafeCfg, "config.failsafe_served", events.SeverityWarning, "serve", classifyFailureReason(err), err.Error(), "exact_lkg")
			return failsafeCfg, nil
		}
		if explicitCfg, explicitErr := l.loadExplicitFailsafeOriginConfig(ctx, hostname, parent, m); explicitErr == nil {
			eventType := "config.validation_failed"
			if strings.Contains(strings.ToLower(err.Error()), "compile") || strings.Contains(strings.ToLower(err.Error()), "lua") || strings.Contains(strings.ToLower(err.Error()), "cel") {
				eventType = "config.compile_failed"
			}
			emitConfigEvent(ctx, explicitCfg, eventType, events.SeverityError, "validate", classifyFailureReason(err), err.Error(), "")
			emitConfigEvent(ctx, explicitCfg, "config.failsafe_served", events.SeverityWarning, "serve", configReasonExplicitFailsafe, err.Error(), "explicit_failsafe")
			return explicitCfg, nil
		}
		return nil, err
	}
	cfg.Parent = parent
	ensureConfigID(cfg, hostname)
	cfg.ConfigMode = configModeActive
	cfg.ConfigReason = ""

	l.configureLoadedConfig(cfg, m)
	l.saveFailsafeSnapshot(hostname, cfg, data)

	slog.Debug("config loaded from storage", "hostname", hostname, "config_id", cfg.ID, "forward_rules_count", len(cfg.ForwardRules))

	// Cache with workspace partition for tenant isolation
	// Use simple hostname if no workspace context (backward compatibility, testing)
	// With workspace: workspace_id:config_id:hostname
	if cfg.WorkspaceID != "" {
		cacheKey = fmt.Sprintf("%s:%s:%s", cfg.WorkspaceID, cfg.ID, hostname)
		l.cacheConfig(cacheKey, cfg)
	}
	cacheKey = hostname
	l.cacheConfig(cacheKey, cfg)

	// Track active origin
	metric.OriginActive(hostname, cfg.WorkspaceID, cfg.ID)

	// Record config reload success
	metric.ConfigReload(hostname, "success")

	if fwdCfg, fwdErr := l.applyForwardRules(ctx, req, cfg, hostname, depth, m, ""); fwdCfg != nil || fwdErr != nil {
		return fwdCfg, fwdErr
	}

	// Check must_match_rules before returning freshly loaded config
	if !checkMustMatchRules(cfg, req) {
		slog.Debug("request does not match must_match_rules, skipping origin",
			"config_id", cfg.ID,
			"hostname", hostname,
			"path", req.URL.Path,
			"method", req.Method)
		metric.RequestRuleRejection(cfg.ID)
		return &config.Config{
			Hostname: hostname,
			ID:       "rules-not-matched",
			Disabled: true,
		}, nil
	}

	return cfg, nil
}

// checkMustMatchRules checks if the request matches the must_match_rules criteria.
// Returns true if the request should proceed (rules not set, must_match disabled, or rules match).
func checkMustMatchRules(cfg *config.Config, req *http.Request) bool {
	if !cfg.MustMatchRules || len(cfg.RequestRules) == 0 {
		return true
	}
	return cfg.RequestRules.Match(req)
}

// ensureConfigID sets cfg.ID to "local-{hostname}" when empty to avoid cache key
// collisions when multiple origins omit id. Hostname colons (e.g. from ports) are
// replaced with hyphens for safe use in IDs.
func ensureConfigID(cfg *config.Config, hostname string) {
	if cfg.ID != "" {
		return
	}
	safe := strings.ReplaceAll(hostname, ":", "-")
	cfg.ID = "local-" + safe
}

func (l *Loader) configureLoadedConfig(cfg *config.Config, m manager.Manager) {
	// Set L3 cache on config for error page caching
	if l3Cache := m.GetCache(manager.L3Cache); l3Cache != nil {
		cfg.SetL3Cache(l3Cache)
	}

	// Initialize vault manager for new-format vault-based secrets.
	setupVaultManager(cfg, m)

	// Setup cookie jar if sessions and cookie jar are enabled
	setupCookieJar(cfg)

	// Set fallback loader to avoid import cycle (config -> configloader)
	if cfg.FallbackOrigin != nil {
		cfg.FallbackLoader = func(ctx context.Context, req *http.Request, fallback *config.FallbackOrigin) (*config.Config, error) {
			return l.loadFallbackConfig(ctx, req, fallback, m, cfg)
		}
	}

	// Set MCP origin loaders for proxy handler origin routing.
	// OriginConfigLoader resolves an existing origin by hostname and compiles it.
	cfg.OriginConfigLoader = func(hostname string) (http.Handler, error) {
		req, _ := http.NewRequest("GET", "/", nil)
		req.Host = hostname
		resolved, err := l.getConfigByHostname(context.Background(), req, hostname, 0, m, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve origin %q: %w", hostname, err)
		}
		if resolved == nil || resolved.Disabled {
			return nil, fmt.Errorf("origin %q not found or disabled", hostname)
		}
		raw := configToRawOrigin(resolved)
		compiled, err := config.CompileOrigin(raw, config.NewServiceProvider(resolved))
		if err != nil {
			return nil, fmt.Errorf("failed to compile origin %q: %w", hostname, err)
		}
		return compiled, nil
	}
	// EmbeddedConfigLoader loads an inline origin config and compiles it.
	cfg.EmbeddedConfigLoader = func(data []byte) (http.Handler, error) {
		resolved, err := loadEmbeddedConfig(data, cfg, m)
		if err != nil {
			return nil, fmt.Errorf("failed to load embedded origin config: %w", err)
		}
		if resolved == nil || resolved.Disabled {
			return nil, fmt.Errorf("embedded origin not found or disabled")
		}
		raw := configToRawOrigin(resolved)
		compiled, err := config.CompileOrigin(raw, config.NewServiceProvider(resolved))
		if err != nil {
			return nil, fmt.Errorf("failed to compile embedded origin: %w", err)
		}
		return compiled, nil
	}
}

func (l *Loader) saveFailsafeSnapshot(hostname string, cfg *config.Config, raw []byte) {
	if cfg == nil || cfg.Disabled || hostname == "" || len(raw) == 0 {
		return
	}
	l.failsafeSnapshots.save(hostname, cfg.WorkspaceID, cfg.Version, cfg.Revision, raw, cfg.FailsafeOrigin)
}

func (l *Loader) loadFailsafeSnapshotConfig(ctx context.Context, hostname string, parent *config.Config, m manager.Manager, reason string, detail string) (*config.Config, error) {
	snapshot, ok := l.failsafeSnapshots.load(hostname)
	if !ok {
		return nil, fmt.Errorf("%s: %s", configReasonSnapshotUnavailable, hostname)
	}

	cfg, err := config.Load(snapshot.Payload)
	if err != nil {
		emitConfigEventFromSnapshot(ctx, snapshot, "config.active_snapshot_corrupt", events.SeverityCritical, "startup", configReasonSnapshotCorrupt, err.Error(), "")
		return nil, err
	}

	cfg.Parent = parent
	ensureConfigID(cfg, hostname)
	cfg.ConfigMode = configModeFailsafe
	cfg.ConfigReason = reason
	if cfg.Revision == "" {
		cfg.Revision = snapshot.Revision
	}

	l.configureLoadedConfig(cfg, m)
	if detail != "" && reason == configReasonSnapshotUnavailable {
		cfg.ConfigReason = detail
	}
	return cfg, nil
}

func (l *Loader) loadExplicitFailsafeOriginConfig(ctx context.Context, hostname string, parent *config.Config, m manager.Manager) (*config.Config, error) {
	snapshot, ok := l.failsafeSnapshots.load(hostname)
	if !ok || snapshot.FailsafeOrigin == nil {
		return nil, fmt.Errorf("no configured failsafe origin for hostname %s", hostname)
	}
	currentDepth := getExplicitFailsafeDepth(ctx)
	maxDepth := getMaxOriginRecursionDepth(m)
	if currentDepth >= maxDepth {
		return nil, ErrMaxFallbackDepthReached
	}
	ctx = withExplicitFailsafeDepth(ctx, currentDepth+1)
	cfg, err := l.resolveFailsafeOrigin(ctx, snapshot.FailsafeOrigin, parent, m)
	if err != nil {
		return nil, err
	}
	cfg.ConfigMode = configModeFailsafe
	cfg.ConfigReason = configReasonExplicitFailsafe
	return cfg, nil
}

func (l *Loader) resolveFailsafeOrigin(ctx context.Context, failsafeOrigin *config.FailsafeOrigin, parent *config.Config, m manager.Manager) (*config.Config, error) {
	if failsafeOrigin == nil {
		return nil, fmt.Errorf("failsafe origin is nil")
	}
	if failsafeOrigin.HasEmbeddedOrigin() {
		cfg, err := l.loadEmbeddedConfig(failsafeOrigin.Origin, parent, m)
		if err != nil {
			return nil, err
		}
		return cfg, nil
	}
	if failsafeOrigin.Hostname == "" {
		return nil, fmt.Errorf("failsafe origin must define hostname or origin")
	}
	cfg, err := l.getConfigByHostname(ctx, nilRequestForHostname(failsafeOrigin.Hostname), failsafeOrigin.Hostname, 0, m, parent)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func nilRequestForHostname(hostname string) *http.Request {
	req, _ := http.NewRequest(http.MethodGet, "http://"+hostname+"/", nil)
	req.Host = hostname
	return req
}

func classifyFailureReason(err error) string {
	if err == nil {
		return configReasonLoadFailed
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "validation"):
		return configReasonValidationFailed
	case strings.Contains(lower, "unmarshal"), strings.Contains(lower, "parse"):
		return configReasonLoadFailed
	case strings.Contains(lower, "lua"), strings.Contains(lower, "cel"), strings.Contains(lower, "compile"):
		return configReasonValidationFailed
	default:
		return configReasonLoadFailed
	}
}

func emitConfigEvent(ctx context.Context, cfg *config.Config, eventType string, severity string, stage string, reason string, detail string, failsafeMode string) {
	if cfg == nil || !cfg.EventEnabled(eventType) {
		return
	}
	event := &events.ConfigLifecycleEvent{
		EventBase:    events.NewBase(eventType, severity, cfg.WorkspaceID, reqctx.GetRequestID(ctx)),
		Stage:        stage,
		Reason:       reason,
		Detail:       detail,
		Revision:     cfg.Revision,
		FailsafeMode: failsafeMode,
		SourceType:   "runtime",
	}
	event.Origin = events.OriginContext{
		OriginID:    cfg.ID,
		OriginName:  cfg.OriginName,
		Hostname:    cfg.Hostname,
		VersionID:   cfg.Version,
		WorkspaceID: cfg.WorkspaceID,
		Environment: cfg.Environment,
		Tags:        cfg.Tags,
	}
	events.Emit(ctx, cfg.WorkspaceID, event)
}

func emitConfigEventFromSnapshot(ctx context.Context, snapshot *failsafeSnapshot, eventType string, severity string, stage string, reason string, detail string, failsafeMode string) {
	if snapshot == nil || snapshot.WorkspaceID == "" {
		return
	}
	event := &events.ConfigLifecycleEvent{
		EventBase:    events.NewBase(eventType, severity, snapshot.WorkspaceID, reqctx.GetRequestID(ctx)),
		Stage:        stage,
		Reason:       reason,
		Detail:       detail,
		Revision:     snapshot.Revision,
		FailsafeMode: failsafeMode,
		SourceType:   "snapshot",
	}
	event.Origin = events.OriginContext{
		Hostname:    snapshot.Hostname,
		VersionID:   snapshot.Version,
		WorkspaceID: snapshot.WorkspaceID,
	}
	events.Emit(ctx, snapshot.WorkspaceID, event)
}

func setupVaultManager(cfg *config.Config, m manager.Manager) {
	if cfg == nil || len(cfg.SecretsMap) == 0 {
		return
	}
	if cfg.GetVaultManager() != nil {
		return
	}

	localCache := m.GetCache(manager.L2Cache)
	if localCache == nil {
		localCache = m.GetCache(manager.L3Cache)
	}
	if localCache == nil {
		slog.Warn("vault secrets configured but no cache backend available",
			"origin_id", cfg.ID,
			"hostname", cfg.Hostname,
			"secret_count", len(cfg.SecretsMap))
		return
	}

	localProvider := vault.NewLocalVaultProvider(localCache)
	vm, err := vault.NewVaultManager(localProvider)
	if err != nil {
		slog.Error("failed to create vault manager",
			"origin_id", cfg.ID,
			"hostname", cfg.Hostname,
			"error", err)
		return
	}
	mergedVaults := vault.MergeVaults(vault.GetServerVaults(), cfg.Vaults)
	vm.SetVaultDefinitions(mergedVaults)
	vm.SetWorkspaceID(cfg.WorkspaceID)
	vm.SetSecretDefinitions(cfg.SecretsMap)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := vm.ResolveAll(ctx); err != nil {
		slog.Error("failed to resolve vault secrets",
			"origin_id", cfg.ID,
			"hostname", cfg.Hostname,
			"secret_count", len(cfg.SecretsMap),
			"vault_count", len(cfg.Vaults),
			"error", err)
		return
	}

	cfg.SetVaultManager(vm)

	// Re-run secret field processing with the resolved vault manager so
	// secret-tagged config fields can consume inline vault references and
	// {{secrets.NAME}} templates without mutating the top-level secrets map.
	decryptor, err := crypto.NewDecryptorFromEnv()
	if err != nil {
		slog.Warn("failed to initialize decryptor while processing resolved vault secrets", "error", err)
		decryptor = nil
	}
	originalSecretsMap := cfg.SecretsMap
	cfg.SecretsMap = nil
	if err := vault.ProcessSecretFields(cfg, nil, decryptor, vm); err != nil {
		slog.Error("failed to process secret fields with resolved vault secrets",
			"origin_id", cfg.ID,
			"hostname", cfg.Hostname,
			"error", err)
		cfg.SecretsMap = originalSecretsMap
		return
	}
	cfg.SecretsMap = originalSecretsMap

	slog.Info("vault manager initialized",
		"origin_id", cfg.ID,
		"hostname", cfg.Hostname,
		"secret_count", len(cfg.SecretsMap),
		"vault_count", len(cfg.Vaults))
}

func (l *Loader) loadEmbeddedConfig(data []byte, parent *config.Config, m manager.Manager) (*config.Config, error) {
	cfg, err := config.Load(data)
	if err != nil {
		return nil, err
	}
	cfg.Parent = parent
	l.configureLoadedConfig(cfg, m)
	return cfg, nil
}

// loadEmbeddedConfig is the package-level compatibility wrapper used by LoadFallbackConfig.
func loadEmbeddedConfig(data []byte, parent *config.Config, m manager.Manager) (*config.Config, error) {
	return defaultLoader.loadEmbeddedConfig(data, parent, m)
}

// DrainWorkspace marks a workspace as draining on this loader. New requests will be rejected with 503.
func (l *Loader) DrainWorkspace(workspaceID string) {
	l.drainedWorkspaces.Store(workspaceID, true)
	slog.Info("workspace marked as draining", "workspace_id", workspaceID)
}

// UndrainWorkspace removes the drain mark from a workspace on this loader.
func (l *Loader) UndrainWorkspace(workspaceID string) {
	l.drainedWorkspaces.Delete(workspaceID)
	slog.Info("workspace drain removed", "workspace_id", workspaceID)
}

// IsWorkspaceDraining returns whether a workspace is currently being drained on this loader.
func (l *Loader) IsWorkspaceDraining(workspaceID string) bool {
	_, draining := l.drainedWorkspaces.Load(workspaceID)
	return draining
}

// DrainWorkspace is the package-level compatibility wrapper.
//
// Deprecated: Use Loader.DrainWorkspace() instead.
func DrainWorkspace(workspaceID string) {
	defaultLoader.DrainWorkspace(workspaceID)
}

// UndrainWorkspace is the package-level compatibility wrapper.
//
// Deprecated: Use Loader.UndrainWorkspace() instead.
func UndrainWorkspace(workspaceID string) {
	defaultLoader.UndrainWorkspace(workspaceID)
}

// IsWorkspaceDraining is the package-level compatibility wrapper.
//
// Deprecated: Use Loader.IsWorkspaceDraining() instead.
func IsWorkspaceDraining(workspaceID string) bool {
	return defaultLoader.IsWorkspaceDraining(workspaceID)
}

func getMaxOriginRecursionDepth(m manager.Manager) int {
	settings := m.GetGlobalSettings().OriginLoaderSettings
	if settings.MaxOriginRecursionDepth > 0 {
		return settings.MaxOriginRecursionDepth
	}
	if settings.MaxOriginForwardDepth > 0 {
		return settings.MaxOriginForwardDepth
	}
	return DefaultMaxForwardDepth
}

// setupCookieJar initializes the cookie jar for session-based cookie storage
func setupCookieJar(cfg *config.Config) {
	// Skip if sessions are disabled or cookie jar is not enabled
	if cfg.SessionConfig.Disabled || !cfg.SessionConfig.EnableCookieJar {
		return
	}

	// Import session package for cookie jar creation
	// Get configuration or use defaults
	opts := session.DefaultCookieJarOptions()
	if cfg.SessionConfig.CookieJarConfig != nil {
		if cfg.SessionConfig.CookieJarConfig.MaxCookies > 0 {
			opts.MaxCookies = cfg.SessionConfig.CookieJarConfig.MaxCookies
		}
		if cfg.SessionConfig.CookieJarConfig.MaxCookieSize > 0 {
			opts.MaxCookieSize = cfg.SessionConfig.CookieJarConfig.MaxCookieSize
		}
		opts.StoreSecureOnly = cfg.SessionConfig.CookieJarConfig.StoreSecureOnly
		opts.StoreHttpOnly = !cfg.SessionConfig.CookieJarConfig.DisableStoreHttpOnly
	}

	// Create cookie jar function and setup the config
	cookieJarFn := session.CreateSessionCookieJarFn(opts)
	cfg.SetupCookieJar(cookieJarFn)
}
