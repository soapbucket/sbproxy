// Package models defines shared data types, constants, and request/response models used across packages.
package reqctx

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HeaderPool is a pool of http.Header objects to reduce allocations
var HeaderPool = sync.Pool{
	New: func() interface{} {
		return make(http.Header)
	},
}

// CloneHeader copies src header to a pooled header.
// Uses a single backing slice for all header values to reduce allocations.
func CloneHeader(src http.Header) http.Header {
	if src == nil {
		return nil
	}
	dst := HeaderPool.Get().(http.Header)
	clear(dst)

	// Count total values to allocate one backing slice
	nv := 0
	for _, vv := range src {
		nv += len(vv)
	}
	sv := make([]string, nv) // single allocation for all values
	for k, vv := range src {
		n := copy(sv, vv)
		dst[k] = sv[:n:n]
		sv = sv[n:]
	}
	return dst
}

// RequestDataPool is a pool of RequestData objects to reduce allocations
var RequestDataPool = sync.Pool{
	New: func() interface{} {
		return &RequestData{
			Config:  make(map[string]any, 16),
			Secrets: make(map[string]string, 4),
		}
	},
}

// Release returns the RequestData to the pool
func (r *RequestData) Release() {
	if r == nil {
		return
	}

	if r.OriginalRequest != nil {
		r.OriginalRequest.Release()
	}

	// Release CELContext if it exists
	if r.CELContext != nil {
		if releasable, ok := r.CELContext.(interface{ Release() }); ok {
			releasable.Release()
		}
		r.CELContext = nil
	}

	// Clear maps to avoid memory leaks and ensure fresh state
	clear(r.DebugHeaders)
	clear(r.Config)
	clear(r.Secrets)
	clear(r.Variables)
	r.Env = nil
	clear(r.FeatureFlags)
	clear(r.Data)
	clear(r.lowercaseHeaders)
	clear(r.lowercaseOrigHeaders)

	// Reset pointers and values
	r.ID = ""
	r.Depth = 0
	r.Debug = false
	r.NoCache = false
	r.NoTrace = false
	r.OriginalRequest = nil
	r.SessionData = nil
	r.Visited = nil
	r.Location = nil
	r.UserAgent = nil
	r.Fingerprint = nil
	r.AIUsage = nil
	r.ResponseCacheKey = ""
	r.SignatureCacheKey = ""
	r.ResponseCacheHit = false
	r.SignatureCacheHit = false
	r.StartTime = time.Time{}
	r.ProxyKeyID = ""
	r.ProxyKeyName = ""

	// Clear bridge fields (per-origin refs are shared, just nil the pointer)
	r.OriginCtx = nil
	r.ServerCtx = nil
	r.VarsCtx = nil
	r.FeaturesCtx = nil
	r.Snapshot = nil
	r.SessionCtx = nil
	r.ClientCtx = nil
	r.CtxObj = nil

	RequestDataPool.Put(r)
}

// AuthData represents a auth data.
type AuthData struct {
	Type string `json:"type"`

	Data map[string]any `json:"data,omitempty"`
}

// VisitedURL represents a visited url.
type VisitedURL struct {
	URL     string    `json:"url"`
	Visited time.Time `json:"visited"`
}

const (
	// MaxSessionDataEntries is the maximum number of entries allowed in SessionData.Data.
	MaxSessionDataEntries = 100
	// MaxSessionDataBytes is the maximum total size (in bytes) of serialized SessionData.Data.
	MaxSessionDataBytes = 65536
)

// SessionData represents a session data.
type SessionData struct {
	ID        string    `json:"id"`
	Expires   time.Time `json:"expires"`
	CreatedAt time.Time `json:"created_at,omitempty"`

	EncryptedID string `json:"encrypted_id"`

	AuthData *AuthData      `json:"auth_data,omitempty"`
	Visited  []VisitedURL   `json:"visited,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
}

// AddVisitedURL adds a URL to the visited list, keeping only the last 10 URLs.
// Maintains newest-first order by shifting elements in place to avoid allocating
// a new backing array on every call.
func (s *SessionData) AddVisitedURL(url string) {
	if s.Visited == nil {
		s.Visited = make([]VisitedURL, 0, 10)
	}

	visitedURL := VisitedURL{
		URL:     url,
		Visited: time.Now(),
	}

	if len(s.Visited) >= 10 {
		// Shift elements right by 1, dropping the last
		copy(s.Visited[1:], s.Visited[:9])
	} else {
		// Grow slice by 1 and shift right
		s.Visited = s.Visited[:len(s.Visited)+1]
		copy(s.Visited[1:], s.Visited[:len(s.Visited)-1])
	}
	s.Visited[0] = visitedURL
}

// GetLastVisitedURLs returns the last N visited URLs (up to 10)
func (s *SessionData) GetLastVisitedURLs(n int) []VisitedURL {
	if s.Visited == nil {
		return []VisitedURL{}
	}

	if n > 10 {
		n = 10
	}

	if n > len(s.Visited) {
		n = len(s.Visited)
	}

	return s.Visited[:n]
}

// SetSessionDataEntry sets a key-value pair in the SessionData.Data map with bounds checking.
// Returns false if the entry count would exceed MaxSessionDataEntries.
func (s *SessionData) SetSessionDataEntry(key string, value any) bool {
	if s.Data == nil {
		s.Data = make(map[string]any, 8)
	}
	// Allow overwrites of existing keys without counting toward the limit.
	if _, exists := s.Data[key]; !exists && len(s.Data) >= MaxSessionDataEntries {
		slog.Warn("session data entry limit reached, rejecting new entry",
			"key", key,
			"current_entries", len(s.Data),
			"max_entries", MaxSessionDataEntries,
			"session_id", s.ID,
		)
		return false
	}
	s.Data[key] = value
	return true
}

// Location represents a location.
type Location struct {
	Country       string `json:"country,omitempty"`
	CountryCode   string `json:"country_code,omitempty"`
	Continent     string `json:"continent,omitempty"`
	ContinentCode string `json:"continent_code,omitempty"`
	ASN           string `json:"asn,omitempty"`
	ASName        string `json:"as_name,omitempty"`
	ASDomain      string `json:"as_domain,omitempty"`
}

// String returns a human-readable representation of the Location.
func (l *Location) String() string {
	return fmt.Sprintf("country=%s,country_code=%s,continent=%s,continent_code=%s,asn=%s,as_name=%s,as_domain=%s", l.Country, l.CountryCode, l.Continent, l.ContinentCode, l.ASN, l.ASName, l.ASDomain)
}

// UserAgent represents a user agent.
type UserAgent struct {
	Family       string `json:"family,omitempty"`
	Major        string `json:"major,omitempty"`
	Minor        string `json:"minor,omitempty"`
	Patch        string `json:"patch,omitempty"`
	OSFamily     string `json:"os_family,omitempty"`
	OSMajor      string `json:"os_major,omitempty"`
	OSMinor      string `json:"os_minor,omitempty"`
	OSPatch      string `json:"os_patch,omitempty"`
	DeviceFamily string `json:"device_family,omitempty"`
	DeviceBrand  string `json:"device_brand,omitempty"`
	DeviceModel  string `json:"device_model,omitempty"`
}

// String returns a human-readable representation of the UserAgent.
func (u *UserAgent) String() string {
	return fmt.Sprintf("family=%s,major=%s,minor=%s,patch=%s,os_family=%s,os_major=%s,os_minor=%s,os_patch=%s,device_family=%s,device_brand=%s,device_model=%s", u.Family, u.Major, u.Minor, u.Patch, u.OSFamily, u.OSMajor, u.OSMinor, u.OSPatch, u.DeviceFamily, u.DeviceBrand, u.DeviceModel)
}

// Fingerprint represents a fingerprint.
type Fingerprint struct {
	Hash          string        `json:"hash,omitempty"`
	Composite     string        `json:"composite,omitempty"`
	IPHash        string        `json:"ip_hash,omitempty"`
	UserAgentHash string        `json:"user_agent_hash,omitempty"`
	HeaderPattern string        `json:"header_pattern,omitempty"`
	TLSHash       string        `json:"tls_hash,omitempty"`
	CookieCount   int           `json:"cookie_count,omitempty"`
	Version       string        `json:"version,omitempty"`
	ConnDuration  time.Duration `json:"conn_duration,omitempty"`
}

// String returns a human-readable representation of the Fingerprint.
func (f *Fingerprint) String() string {
	return fmt.Sprintf("hash=%s,composite=%s,ip_hash=%s,user_agent_hash=%s,header_pattern=%s,tls_hash=%s,cookie_count=%d,version=%s,conn_duration=%s", f.Hash, f.Composite, f.IPHash, f.UserAgentHash, f.HeaderPattern, f.TLSHash, f.CookieCount, f.Version, f.ConnDuration.String())
}

// AIUsage stores AI proxy request usage data for logging and metrics.
type AIUsage struct {
	Provider        string  `json:"ai_provider,omitempty"`
	Model           string  `json:"ai_model,omitempty"`
	InputTokens     int     `json:"ai_input_tokens,omitempty"`
	OutputTokens    int     `json:"ai_output_tokens,omitempty"`
	TotalTokens     int     `json:"ai_total_tokens,omitempty"`
	CachedTokens    int     `json:"ai_cached_tokens,omitempty"`
	CostUSD         float64 `json:"ai_cost_usd,omitempty"`
	TtftMS          int64   `json:"ai_ttft_ms,omitempty"`
	AvgItlMS        int64   `json:"ai_avg_itl_ms,omitempty"`
	RoutingStrategy string  `json:"ai_routing_strategy,omitempty"`
	Streaming       bool    `json:"ai_streaming,omitempty"`

	// Agent identity fields
	Agent      string `json:"ai_agent,omitempty"`
	SessionID  string `json:"ai_session_id,omitempty"`
	APIKeyName string `json:"ai_api_key_name,omitempty"`

	// Observability fields
	CacheHit          bool    `json:"ai_cached,omitempty"`
	CacheType         string  `json:"ai_cache_type,omitempty"`
	BudgetScope       string  `json:"ai_budget_scope,omitempty"`
	BudgetScopeValue  string  `json:"ai_budget_scope_value,omitempty"`
	BudgetUtilization float64 `json:"ai_budget_utilization,omitempty"`
	ModelDowngraded   bool    `json:"ai_model_downgraded,omitempty"`
	OriginalModel     string  `json:"ai_original_model,omitempty"`
	PromptID          string  `json:"ai_prompt_id,omitempty"`
	PromptEnvironment string  `json:"ai_prompt_environment,omitempty"`
	PromptVersion     int     `json:"ai_prompt_version,omitempty"`

	// Compliance audit fields
	APIKeyHash   string `json:"ai_api_key_hash,omitempty"`  // SHA-256 hash of API key used
	PromptHash   string `json:"ai_prompt_hash,omitempty"`   // SHA-256 hash of prompt content
	ResponseHash string `json:"ai_response_hash,omitempty"` // SHA-256 hash of response content

	// Governance reporting fields
	StreamingGuardrailMode string              `json:"ai_streaming_guardrail_mode,omitempty"`
	ProviderExclusions     []ProviderExclusion `json:"ai_provider_exclusions,omitempty"`

	// Request-level tags from sb_tags for reporting/filtering
	Tags map[string]string `json:"ai_tags,omitempty"`

	// Custom metadata from X-Sb-Meta-* headers
	Metadata map[string]string `json:"ai_metadata,omitempty"`

	// Request ID assigned by the proxy (client-provided or generated)
	RequestID string `json:"ai_request_id,omitempty"`
	// Provider's response ID (e.g., OpenAI's chatcmpl-xxx)
	ProviderRequestID string `json:"ai_provider_request_id,omitempty"`
}

// ProviderExclusion captures why a provider was excluded by policy for governance reporting.
type ProviderExclusion struct {
	Provider  string `json:"provider"`
	Attribute string `json:"attribute"`
	Reason    string `json:"reason"`
}

// RequestData represents a request data.
type RequestData struct {
	ID    string `json:"id"`
	Depth int    `json:"depth"`

	Debug   bool `json:"debug,omitempty"`
	NoCache bool `json:"no_cache,omitempty"`
	NoTrace bool `json:"no_trace,omitempty"`

	DebugHeaders map[string]string `json:"debug_headers,omitempty"`

	// Config stores immutable configuration data from on_load callback
	// This is separate from Data to ensure immutability
	// Use ConfigParams helper methods (GetConfigID, GetWorkspaceID) to access values
	Config map[string]any `json:"config,omitempty"`

	// Secrets stores secrets loaded from secrets callback
	// This is separate from Config and Data to ensure proper access control
	Secrets map[string]string `json:"secrets,omitempty"`

	// Variables stores user-defined config-level variables (immutable)
	// Available in templates as {{ variables.name }} and Lua as variables.name
	Variables map[string]any `json:"variables,omitempty"`

	// Env stores per-origin identity variables (immutable, from config metadata)
	// Available in templates as {{ env.origin_id }} and Lua as env.origin_id
	Env map[string]any `json:"env,omitempty"`

	// FeatureFlags stores workspace-scoped feature flags (from FeatureFlagManager)
	// Available in templates as {{ feature.key }} and Lua as feature.key
	FeatureFlags map[string]any `json:"feature_flags,omitempty"`

	Data map[string]any `json:"data,omitempty"`

	// OriginalRequest stores the original request before any modifications
	// Body is automatically parsed to BodyJSON if Content-Type is application/json
	OriginalRequest *OriginalRequestData `json:"original_request,omitempty"`

	SessionData *SessionData `json:"session_data,omitempty"`
	Visited     []VisitedURL `json:"visited,omitempty"`
	Location    *Location    `json:"location,omitempty"`
	UserAgent   *UserAgent   `json:"user_agent,omitempty"`
	Fingerprint *Fingerprint `json:"fingerprint,omitempty"`

	// AI usage data for logging and metrics
	AIUsage *AIUsage `json:"ai_usage,omitempty"`

	// Cache information for request logging
	ResponseCacheKey  string `json:"response_cache_key,omitempty"`  // Cache key if response cache hit
	SignatureCacheKey string `json:"signature_cache_key,omitempty"` // Cache key if signature cache hit
	ResponseCacheHit  bool   `json:"response_cache_hit,omitempty"`  // Whether response cache was hit
	SignatureCacheHit bool   `json:"signature_cache_hit,omitempty"` // Whether signature cache was hit

	// Request timing for templates and metrics
	StartTime time.Time `json:"start_time,omitempty"` // Request start time

	// Policy violation info for request logging
	Error     string `json:"error,omitempty"`      // Error message when request is blocked
	ErrorType string `json:"error_type,omitempty"` // Category: "rate_limit", "ip_filter", "waf", "auth", "cors", etc.
	ErrorCode string `json:"error_code,omitempty"` // Machine-readable code (e.g., "429", "IP_BLOCKED")

	// Proxy auth info (when authenticated via proxy API key)
	ProxyKeyID   string `json:"proxy_key_id,omitempty"`   // UUID of the authenticated key
	ProxyKeyName string `json:"proxy_key_name,omitempty"` // Human-readable key name (e.g., "production")

	// Cached lowercase header maps — computed once per request, reused across template resolves
	lowercaseHeaders     map[string]string `json:"-"`
	lowercaseOrigHeaders map[string]string `json:"-"`

	// CELContext stores the pooled internal/cel.RequestContext
	// Use any to avoid circular dependency
	CELContext any `json:"-"`

	// Bridge fields for incremental migration to new context model.
	// These are populated alongside old fields by configloader during migration.
	// Once migration is complete, RequestData will be replaced by RequestContextV2.
	OriginCtx   *OriginContext   `json:"-"`
	ServerCtx   *ServerContext   `json:"-"`
	VarsCtx     *VarsContext     `json:"-"`
	FeaturesCtx *FeaturesContext `json:"-"`
	Snapshot    *RequestSnapshot `json:"-"`
	SessionCtx  *SessionContext  `json:"-"`
	ClientCtx   *ClientContext   `json:"-"`
	CtxObj      *CtxObject       `json:"-"`
}

// OriginalRequestData stores the original request data before any modifications
// This allows access to the original request body, headers, etc. in callbacks and templates
type OriginalRequestData struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	Path        string      `json:"path"`
	RawQuery    string      `json:"raw_query"`
	Headers     http.Header `json:"headers"`
	Body        []byte      `json:"body,omitempty"`
	IsJSON      bool        `json:"is_json,omitempty"` // True if Content-Type is application/json
	ContentType string      `json:"content_type"`
	RemoteAddr  string      `json:"remote_addr"`

	// BodyJSON caches the parsed body as JSON to avoid redundant Unmarshal calls
	BodyJSON any `json:"-"`
}

// OriginalRequestDataPool is a pool of OriginalRequestData objects
var OriginalRequestDataPool = sync.Pool{
	New: func() interface{} {
		return &OriginalRequestData{}
	},
}

// Release returns the OriginalRequestData to the pool
func (o *OriginalRequestData) Release() {
	if o == nil {
		return
	}
	if o.Headers != nil {
		HeaderPool.Put(o.Headers)
		o.Headers = nil
	}
	o.Body = nil
	o.BodyJSON = nil
	OriginalRequestDataPool.Put(o)
}

// BodyAsJSON parses the body as JSON and returns the result
// Returns any type: map[string]any for objects, []any for arrays, primitives for literals
// Returns nil if body is empty or not valid JSON
func (o *OriginalRequestData) BodyAsJSON() any {
	if o == nil || len(o.Body) == 0 {
		return nil
	}

	if o.BodyJSON != nil {
		return o.BodyJSON
	}

	var result any
	if err := json.Unmarshal(o.Body, &result); err != nil {
		return nil
	}

	o.BodyJSON = result
	return result
}

// ConfigParams is a type alias for the config parameters map
// It provides type-safe access to configuration parameters stored in RequestData.Config
type ConfigParams map[string]any

// GetConfigID returns the config_id from the config parameters
func (c ConfigParams) GetConfigID() string {
	if c == nil {
		return ""
	}
	if id, ok := c[ConfigParamID].(string); ok {
		return id
	}
	return ""
}

// GetWorkspaceID returns the workspace_id from the config parameters
func (c ConfigParams) GetWorkspaceID() string {
	if c == nil {
		return ""
	}
	if workspaceID, ok := c[ConfigParamWorkspaceID].(string); ok {
		return workspaceID
	}
	return ""
}

// GetVersion returns the version from the config parameters
func (c ConfigParams) GetVersion() string {
	if c == nil {
		return ""
	}
	if version, ok := c[ConfigParamVersion].(string); ok {
		return version
	}
	return ""
}

// GetRevision returns the revision from the config parameters.
func (c ConfigParams) GetRevision() string {
	if c == nil {
		return ""
	}
	if revision, ok := c[ConfigParamRevision].(string); ok {
		return revision
	}
	return ""
}

// GetConfigHostname returns the config_hostname from the config parameters
func (c ConfigParams) GetConfigHostname() string {
	if c == nil {
		return ""
	}
	if hostname, ok := c[ConfigParamHostname].(string); ok {
		return hostname
	}
	return ""
}

// GetParentConfigID returns the parent_config_id from the config parameters
func (c ConfigParams) GetParentConfigID() string {
	if c == nil {
		return ""
	}
	if id, ok := c[ConfigParamParentID].(string); ok {
		return id
	}
	return ""
}

// GetParentConfigHostname returns the parent_config_hostname from the config parameters
func (c ConfigParams) GetParentConfigHostname() string {
	if c == nil {
		return ""
	}
	if hostname, ok := c[ConfigParamParentHostname].(string); ok {
		return hostname
	}
	return ""
}

// GetParentVersion returns the parent_version from the config parameters
func (c ConfigParams) GetParentVersion() string {
	if c == nil {
		return ""
	}
	if version, ok := c[ConfigParamParentVersion].(string); ok {
		return version
	}
	return ""
}

// GetEnvironment returns the environment from the config parameters
func (c ConfigParams) GetEnvironment() string {
	if c == nil {
		return ""
	}
	if env, ok := c[ConfigParamEnvironment].(string); ok {
		return env
	}
	return ""
}

// GetConfigMode returns the serving mode from the config parameters.
func (c ConfigParams) GetConfigMode() string {
	if c == nil {
		return ""
	}
	if mode, ok := c[ConfigParamMode].(string); ok {
		return mode
	}
	return ""
}

// GetConfigReason returns the serving reason from the config parameters.
func (c ConfigParams) GetConfigReason() string {
	if c == nil {
		return ""
	}
	if reason, ok := c[ConfigParamReason].(string); ok {
		return reason
	}
	return ""
}

// GetTags returns the tags from the config parameters
func (c ConfigParams) GetTags() []string {
	if c == nil {
		return nil
	}
	if tags, ok := c[ConfigParamTags].([]string); ok {
		return tags
	}
	// Handle case where tags come from JSON deserialization as []any
	if raw, ok := c[ConfigParamTags].([]any); ok {
		tags := make([]string, 0, len(raw))
		for _, v := range raw {
			if s, ok := v.(string); ok {
				tags = append(tags, s)
			}
		}
		return tags
	}
	return nil
}

// GetEvents returns the event types to emit from the config parameters
func (c ConfigParams) GetEvents() []string {
	if c == nil {
		return nil
	}
	if events, ok := c[ConfigParamEvents].([]string); ok {
		return events
	}
	// Handle case where events come from JSON deserialization as []any
	if raw, ok := c[ConfigParamEvents].([]any); ok {
		events := make([]string, 0, len(raw))
		for _, v := range raw {
			if s, ok := v.(string); ok {
				events = append(events, s)
			}
		}
		return events
	}
	return nil
}

// EventEnabled checks if the event type is registered in the config parameters.
func (c ConfigParams) EventEnabled(eventType string) bool {
	eventsList := c.GetEvents()
	if len(eventsList) == 0 {
		return false
	}
	for _, registered := range eventsList {
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

// AddDebugHeader performs the add debug header operation on the RequestData.
func (r *RequestData) AddDebugHeader(key, value string) {
	if r.DebugHeaders == nil {
		r.DebugHeaders = make(map[string]string, 4)
	}
	r.DebugHeaders[key] = value
}

// GetLowercaseHeaders returns a cached lowercase header map, computing it once per request.
// Keys are lowercased with hyphens replaced by underscores for template dot notation.
func (r *RequestData) GetLowercaseHeaders(headers http.Header) map[string]string {
	if r.lowercaseHeaders == nil {
		r.lowercaseHeaders = headersToLowercaseMap(headers)
	}
	return r.lowercaseHeaders
}

// GetLowercaseOrigHeaders returns a cached lowercase header map for original request headers.
func (r *RequestData) GetLowercaseOrigHeaders(headers http.Header) map[string]string {
	if r.lowercaseOrigHeaders == nil {
		r.lowercaseOrigHeaders = headersToLowercaseMap(headers)
	}
	return r.lowercaseOrigHeaders
}

// headersToLowercaseMap converts http.Header to a map[string]string with lowercase keys.
// Hyphens are converted to underscores for template dot notation access.
func headersToLowercaseMap(headers http.Header) map[string]string {
	if headers == nil {
		return map[string]string{}
	}
	result := make(map[string]string, len(headers))
	for key, values := range headers {
		lowerKey := strings.ToLower(key)
		lowerKey = strings.ReplaceAll(lowerKey, "-", "_")
		if len(values) > 0 {
			result[lowerKey] = values[0]
		} else {
			result[lowerKey] = ""
		}
	}
	return result
}

// SetData sets a key-value pair in the Data map, lazily initializing it if needed.
func (r *RequestData) SetData(key string, value any) {
	if r.Data == nil {
		r.Data = make(map[string]any, 4)
	}
	r.Data[key] = value
}
