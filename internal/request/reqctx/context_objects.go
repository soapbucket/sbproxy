// context_objects.go defines OriginContext, which holds immutable per-origin metadata.
package reqctx

import (
	"net/http"
	"sync"
	"time"
)

// OriginContext holds immutable per-origin data, built once at config load time.
// Consolidates: Config (on_load params), EnvMap (identity), Secrets (vault/provider).
type OriginContext struct {
	// From Config struct metadata (was EnvMap fields)
	ID          string   `json:"id"`
	Hostname    string   `json:"hostname"`
	WorkspaceID string   `json:"workspace_id"`
	Environment string   `json:"environment"`
	Version     string   `json:"version"`
	Revision    string   `json:"revision"`
	Name        string   `json:"name"`
	Tags        []string `json:"tags"`

	// Serving metadata
	ConfigMode   string `json:"config_mode,omitempty"`
	ConfigReason string `json:"config_reason,omitempty"`

	// From on_load callback (was RequestData.Config)
	Params map[string]any `json:"params"`

	// From vault/provider resolution (was RequestData.Secrets)
	Secrets map[string]string `json:"-"`
}

// ServerContext holds process-global immutable state, set once at startup.
// Replaces serverVarsGetter callback pattern.
type ServerContext struct {
	InstanceID  string `json:"instance_id"`
	Version     string `json:"version"`
	BuildHash   string `json:"build_hash"`
	StartTime   string `json:"start_time"`
	Hostname    string `json:"hostname"`
	Environment string `json:"environment"`

	// Custom operator-defined variables from sb.yml "var" section
	Custom map[string]string `json:"custom,omitempty"`

	// Env exposes OS environment variables (filtered set, not full os.Environ)
	Env map[string]string `json:"env,omitempty"`
}

// ToMap converts ServerContext to a flat map for template/Lua compatibility.
// Built-in fields are top-level, custom vars are merged in (no collisions enforced at build time).
func (s *ServerContext) ToMap() map[string]any {
	if s == nil {
		return map[string]any{}
	}
	m := map[string]any{
		"instance_id": s.InstanceID,
		"version":     s.Version,
		"build_hash":  s.BuildHash,
		"start_time":  s.StartTime,
		"hostname":    s.Hostname,
		"environment": s.Environment,
	}
	// Merge custom vars (already validated for no collisions)
	for k, v := range s.Custom {
		m[k] = v
	}
	if s.Env != nil {
		m["env"] = s.Env
	}
	return m
}

// VarsContext wraps user-defined config-level variables (immutable per-origin).
// Was: RequestData.Variables / config.Variables
type VarsContext struct {
	Data map[string]any `json:"data,omitempty"`
}

// FeaturesContext wraps workspace-scoped feature flags (read-only per-request).
// Was: RequestData.FeatureFlags
type FeaturesContext struct {
	Data map[string]any `json:"data,omitempty"`
}

// RequestSnapshot captures the original incoming request before any modifications.
// Was: OriginalRequestData
type RequestSnapshot struct {
	Method      string              `json:"method"`
	Path        string              `json:"path"`
	URL         string              `json:"url"`
	Query       map[string][]string `json:"query"`
	Headers     map[string]string   `json:"headers"`
	RemoteAddr  string              `json:"remote_addr"`
	Body        []byte              `json:"body,omitempty"`
	BodyJSON    any                 `json:"body_json,omitempty"`
	ContentType string              `json:"content_type"`
	IsJSON      bool                `json:"is_json,omitempty"`
	Host        string              `json:"host"`
}

// SessionContext provides read-only access to session state.
// Was: RequestData.SessionData
type SessionContext struct {
	ID   string         `json:"id"`
	Data map[string]any `json:"data"`
	Auth SessionAuth    `json:"auth"`
}

// SessionAuth holds authentication data within a session.
type SessionAuth struct {
	Type string         `json:"type"`
	Data map[string]any `json:"data"`
}

// ClientContext holds client identity data detected by middleware.
// Was: RequestData.Location, UserAgent, Fingerprint (separate fields)
type ClientContext struct {
	IP          string       `json:"ip"`
	Location    *Location    `json:"location,omitempty"`
	UserAgent   *UserAgent   `json:"user_agent,omitempty"`
	Fingerprint *Fingerprint `json:"fingerprint,omitempty"`
}

// CtxObject is the per-request mutable state and live request/response reference.
// Was: RequestData.Data + the live request + response phase data
type CtxObject struct {
	// Request identity
	ID        string    `json:"id"`
	StartTime time.Time `json:"start_time"`

	// Mutable plugin state (read/write by Lua, WASM, callbacks)
	Data map[string]any `json:"data"`

	// Response data (populated after upstream call, for response-phase plugins)
	Response CtxResponse `json:"response"`

	// Cache status
	CacheStatus string `json:"cache_status"`

	// Internal fields (not exposed to plugins)
	Debug        bool              `json:"-"`
	NoCache      bool              `json:"-"`
	NoTrace      bool              `json:"-"`
	DebugHeaders map[string]string `json:"-"`
	AIUsage      *AIUsage          `json:"-"`
	ProxyKeyID   string            `json:"-"`
	ProxyKeyName string            `json:"-"`
	CELContext   any               `json:"-"`

	// Cache keys (internal)
	ResponseCacheKey  string `json:"-"`
	SignatureCacheKey string `json:"-"`
	ResponseCacheHit  bool   `json:"-"`
	SignatureCacheHit bool   `json:"-"`
}

// CtxResponse holds response-phase data for plugins.
type CtxResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body,omitempty"`
}

// SetData sets a key-value pair in the ctx Data map, lazily initializing if needed.
func (c *CtxObject) SetData(key string, value any) {
	if c.Data == nil {
		c.Data = make(map[string]any, 4)
	}
	c.Data[key] = value
}

// AddDebugHeader adds a debug header to the ctx.
func (c *CtxObject) AddDebugHeader(key, value string) {
	if c.DebugHeaders == nil {
		c.DebugHeaders = make(map[string]string, 4)
	}
	c.DebugHeaders[key] = value
}

// RequestContextV2 is the unified request context organized into 9 namespaces:
//
//  1. Origin   - per-origin immutable metadata (ID, hostname, workspace, params, secrets)
//  2. Server   - process-global immutable state (version, hostname, custom vars)
//  3. Vars     - user-defined config-level variables (immutable per-origin)
//  4. Features - workspace-scoped feature flags (read-only per-request)
//  5. Request  - immutable snapshot of the original incoming request
//  6. Client   - client identity data (IP, geo, UA, fingerprint)
//  7. Session  - read-only session state
//  8. Ctx      - per-request mutable state (plugin data, response phase, cache keys)
//  9. Secrets  - resolved secrets from vault (exposed only at the top-level template context)
//
// Per-origin objects (1-4) are shared across requests for the same origin.
// Per-request objects (5-8) are unique to each request and pooled for reuse.
type RequestContextV2 struct {
	// Per-origin (immutable, shared across requests for same origin)
	Origin   *OriginContext   `json:"origin,omitempty"`
	Server   *ServerContext   `json:"server,omitempty"`
	Vars     *VarsContext     `json:"vars,omitempty"`
	Features *FeaturesContext `json:"features,omitempty"`

	// Per-request (immutable snapshot)
	Request *RequestSnapshot `json:"request,omitempty"`
	Client  *ClientContext   `json:"client,omitempty"`

	// Per-session (read-only to plugins)
	Session *SessionContext `json:"session,omitempty"`

	// Per-request mutable state
	Ctx *CtxObject `json:"ctx,omitempty"`

	// Live HTTP request reference (for template resolver building ctx.request)
	LiveRequest *http.Request `json:"-"`

	// Depth for forward rule recursion
	Depth int `json:"-"`

	// Visited URLs for session tracking
	Visited []VisitedURL `json:"-"`

	// Cached lowercase header maps (computed once per request, reused across resolves)
	lowercaseHeaders     map[string]string `json:"-"`
	lowercaseOrigHeaders map[string]string `json:"-"`
}

// RequestContextV2Pool is a pool of RequestContextV2 objects to reduce allocations.
var RequestContextV2Pool = sync.Pool{
	New: func() interface{} {
		return &RequestContextV2{
			Ctx: &CtxObject{
				Data: make(map[string]any, 4),
			},
		}
	},
}

// NewRequestContextV2 creates a new RequestContextV2 from the pool.
func NewRequestContextV2() *RequestContextV2 {
	return RequestContextV2Pool.Get().(*RequestContextV2)
}

// ReleaseV2 returns the RequestContextV2 to the pool after zeroing all fields.
// Oversized maps are nil'd out (not cleared) to prevent retaining large backing
// arrays that would waste memory across pool reuse cycles.
func (rc *RequestContextV2) ReleaseV2() {
	if rc == nil {
		return
	}

	// Release CELContext if it exists
	if rc.Ctx != nil && rc.Ctx.CELContext != nil {
		if releasable, ok := rc.Ctx.CELContext.(interface{ Release() }); ok {
			releasable.Release()
		}
		rc.Ctx.CELContext = nil
	}

	// Clear maps (nil out oversized maps to prevent retaining large backing arrays)
	if rc.Ctx != nil {
		rc.Ctx.Data = clearOrNilMap(rc.Ctx.Data)
		rc.Ctx.DebugHeaders = clearOrNilMap(rc.Ctx.DebugHeaders)
		rc.Ctx.ID = ""
		rc.Ctx.StartTime = time.Time{}
		rc.Ctx.Debug = false
		rc.Ctx.NoCache = false
		rc.Ctx.NoTrace = false
		rc.Ctx.AIUsage = nil
		rc.Ctx.CacheStatus = ""
		rc.Ctx.ProxyKeyID = ""
		rc.Ctx.ProxyKeyName = ""
		rc.Ctx.ResponseCacheKey = ""
		rc.Ctx.SignatureCacheKey = ""
		rc.Ctx.ResponseCacheHit = false
		rc.Ctx.SignatureCacheHit = false
		rc.Ctx.Response = CtxResponse{}
	}

	rc.lowercaseHeaders = clearOrNilMap(rc.lowercaseHeaders)
	rc.lowercaseOrigHeaders = clearOrNilMap(rc.lowercaseOrigHeaders)

	// Reset pointers (per-origin refs are shared, don't clear their contents)
	rc.Origin = nil
	rc.Server = nil
	rc.Vars = nil
	rc.Features = nil
	rc.Request = nil
	rc.Client = nil
	rc.Session = nil
	rc.LiveRequest = nil
	rc.Depth = 0
	rc.Visited = nil

	RequestContextV2Pool.Put(rc)
}

// GetLowercaseHeaders returns a cached lowercase header map for the live request.
func (rc *RequestContextV2) GetLowercaseHeaders(headers http.Header) map[string]string {
	if rc.lowercaseHeaders == nil {
		rc.lowercaseHeaders = headersToLowercaseMap(headers)
	}
	return rc.lowercaseHeaders
}

// GetLowercaseOrigHeaders returns a cached lowercase header map for the original request snapshot.
func (rc *RequestContextV2) GetLowercaseOrigHeaders(headers http.Header) map[string]string {
	if rc.lowercaseOrigHeaders == nil {
		rc.lowercaseOrigHeaders = headersToLowercaseMap(headers)
	}
	return rc.lowercaseOrigHeaders
}

// BuildSessionContext creates a SessionContext from existing SessionData.
func BuildSessionContext(sd *SessionData) *SessionContext {
	if sd == nil {
		return nil
	}
	sc := &SessionContext{
		ID:   sd.ID,
		Data: sd.Data,
	}
	if sd.AuthData != nil {
		sc.Auth = SessionAuth{
			Type: sd.AuthData.Type,
			Data: sd.AuthData.Data,
		}
	}
	return sc
}

// BuildRequestSnapshot creates a RequestSnapshot from an OriginalRequestData.
func BuildRequestSnapshot(ord *OriginalRequestData) *RequestSnapshot {
	if ord == nil {
		return nil
	}
	rs := &RequestSnapshot{
		Method:      ord.Method,
		Path:        ord.Path,
		URL:         ord.GetURL(),
		RemoteAddr:  ord.RemoteAddr,
		Body:        ord.Body,
		ContentType: ord.ContentType,
		IsJSON:      ord.IsJSON,
	}
	// Convert headers to lowercase map (triggers lazy clone if needed)
	if h := ord.GetHeaders(); h != nil {
		rs.Headers = headersToLowercaseMap(h)
	}
	// Parse query from URL
	if ord.RawQuery != "" {
		rs.URL = ord.GetURL()
	}
	// Parse body JSON if applicable
	if ord.IsJSON && len(ord.Body) > 0 {
		rs.BodyJSON = ord.BodyAsJSON()
	}
	return rs
}

// BuildClientContext creates a ClientContext from enrichment data on RequestData.
func BuildClientContext(remoteAddr string, loc *Location, ua *UserAgent, fp *Fingerprint) *ClientContext {
	return &ClientContext{
		IP:          remoteAddr,
		Location:    loc,
		UserAgent:   ua,
		Fingerprint: fp,
	}
}
