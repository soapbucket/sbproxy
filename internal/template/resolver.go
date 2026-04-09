// Package template evaluates Mustache templates for dynamic configuration values and response generation.
package template

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cbroglie/mustache"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// Resolver handles all Mustache template resolution in the proxy.
// Implements template caching for performance optimization.
type Resolver struct {
	cache sync.Map // map[string]*mustache.Template - thread-safe cache
}

var globalResolver = newResolver()

// serverVarsGetter is a callback to retrieve server variables without creating
// an import cycle. Set by the service layer at startup.
var serverVarsGetter func() map[string]any

// SetServerVarsGetter registers the function used to retrieve server variables.
func SetServerVarsGetter(fn func() map[string]any) {
	serverVarsGetter = fn
}

// featureFlagGetter is a callback to retrieve feature flags for a workspace
// without creating an import cycle. Set by the service layer at startup.
var featureFlagGetter func(ctx context.Context, workspaceID string) map[string]any

// SetFeatureFlagGetter registers the function used to retrieve feature flags.
func SetFeatureFlagGetter(fn func(ctx context.Context, workspaceID string) map[string]any) {
	featureFlagGetter = fn
}

func newResolver() *Resolver {
	return &Resolver{}
}

// bufPool provides reusable bytes.Buffer for template execution.
var bufPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

// Singleton empty maps to avoid per-call allocations in context building fallback paths.
var (
	emptyStringMap = map[string]string{}
	emptyAnyMap    = map[string]any{}
	emptyQueryMap  = map[string][]string{}
)

// Resolve resolves a Mustache template with request context.
// Used in: rules, modifiers, transforms, forward rules.
func Resolve(template string, req *http.Request) (string, error) {
	return globalResolver.Resolve(template, req)
}

// ResolveWithContext resolves a Mustache template with a pre-built context map.
// Used by callback body, orchestration, MCP, transform, error pages.
func ResolveWithContext(template string, ctx map[string]any) (string, error) {
	return globalResolver.ResolveWithContext(template, ctx)
}

// Resolve resolves a template string with the request context.
func (r *Resolver) Resolve(template string, req *http.Request) (string, error) {
	// Fast path: skip parsing if no template markers
	if !strings.Contains(template, "{{") {
		return template, nil
	}

	// Get or compile template (cached)
	tpl, err := r.getTemplate(template)
	if err != nil {
		return "", fmt.Errorf("template compilation failed: %w", err)
	}

	// Build context from request
	ctx := r.buildContextMap(req)

	// Execute template
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	if err := tpl.FRender(buf, ctx); err != nil {
		// Return partial output on error (backward compatibility)
		return buf.String(), nil
	}

	return buf.String(), nil
}

// ResolveWithContext resolves a template with a pre-built context map.
func (r *Resolver) ResolveWithContext(template string, ctx map[string]any) (string, error) {
	// Fast path: skip parsing if no template markers
	if !strings.Contains(template, "{{") {
		return template, nil
	}

	// Get or compile template (cached)
	tpl, err := r.getTemplate(template)
	if err != nil {
		return "", fmt.Errorf("template compilation failed: %w", err)
	}

	// Execute template
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	if err := tpl.FRender(buf, ctx); err != nil {
		// Return partial output on error (backward compatibility)
		return buf.String(), nil
	}

	return buf.String(), nil
}

// getTemplate retrieves a compiled template from cache or compiles it.
func (r *Resolver) getTemplate(templateStr string) (*mustache.Template, error) {
	// Check cache first
	if cached, ok := r.cache.Load(templateStr); ok {
		return cached.(*mustache.Template), nil
	}

	// Compile template with forceRaw=true to disable HTML escaping.
	// The proxy produces headers, URLs, and API responses - not HTML.
	tpl, err := mustache.ParseStringRaw(templateStr, true)
	if err != nil {
		return nil, err
	}

	// Store in cache
	r.cache.Store(templateStr, tpl)

	return tpl, nil
}

// BuildContext builds a comprehensive template context from the request.
// Exported for use in transforms and other components.
// Returns map[string]any for compatibility with existing callers.
func BuildContext(req *http.Request) map[string]any {
	return globalResolver.buildContextMap(req)
}

// buildContextMap builds a map[string]any context (for external use).
func (r *Resolver) buildContextMap(req *http.Request) map[string]any {
	if req == nil {
		return map[string]any{}
	}

	rd := reqctx.GetRequestData(req.Context())
	if rd == nil {
		return map[string]any{}
	}

	return r.buildContextMapFromRD(req, rd)
}

// buildContextMapFromRD builds the template context map from request and RequestData.
// Produces the 9-namespace model: origin, server, vars, features, request, session,
// client, ctx, cache.
func (r *Resolver) buildContextMapFromRD(req *http.Request, rd *reqctx.RequestData) map[string]any {
	// Helper function to extract IP from remote address (strip port)
	remoteAddr := req.RemoteAddr
	if remoteAddr != "" {
		if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
			remoteAddr = host
		}
	}

	// --- New namespace: origin ---
	originCtx := emptyAnyMap
	if rd.OriginCtx != nil {
		originCtx = map[string]any{
			"id":            rd.OriginCtx.ID,
			"hostname":      rd.OriginCtx.Hostname,
			"workspace_id":  rd.OriginCtx.WorkspaceID,
			"environment":   rd.OriginCtx.Environment,
			"version":       rd.OriginCtx.Version,
			"revision":      rd.OriginCtx.Revision,
			"name":          rd.OriginCtx.Name,
			"tags":          rd.OriginCtx.Tags,
			"config_mode":   rd.OriginCtx.ConfigMode,
			"config_reason": rd.OriginCtx.ConfigReason,
			"params":        rd.OriginCtx.Params,
		}
	}

	// --- New namespace: server ---
	serverCtx := emptyAnyMap
	if rd.ServerCtx != nil {
		serverCtx = rd.ServerCtx.ToMap()
	} else if serverVarsGetter != nil {
		if sv := serverVarsGetter(); sv != nil {
			serverCtx = sv
		}
	}

	// --- New namespace: vars ---
	var varsCtx map[string]any
	if rd.VarsCtx != nil && rd.VarsCtx.Data != nil {
		varsCtx = rd.VarsCtx.Data
	} else if rd.Variables != nil {
		varsCtx = rd.Variables
	}

	// --- New namespace: features ---
	featuresCtx := emptyAnyMap
	if rd.FeaturesCtx != nil && rd.FeaturesCtx.Data != nil {
		featuresCtx = rd.FeaturesCtx.Data
	} else if featureFlagGetter != nil && rd.Env != nil {
		if wsID, ok := rd.Env["workspace_id"].(string); ok && wsID != "" {
			if flags := featureFlagGetter(context.Background(), wsID); flags != nil {
				featuresCtx = flags
			}
		}
	}

	// --- Namespace: request (immutable snapshot of original request) ---
	requestCtx := make(map[string]any, 16)
	if rd.Snapshot != nil {
		requestCtx["method"] = rd.Snapshot.Method
		requestCtx["path"] = rd.Snapshot.Path
		requestCtx["url"] = rd.Snapshot.URL
		requestCtx["query"] = rd.Snapshot.Query
		requestCtx["headers"] = rd.Snapshot.Headers
		requestCtx["remote_addr"] = rd.Snapshot.RemoteAddr
		requestCtx["host"] = rd.Snapshot.Host
		requestCtx["content_type"] = rd.Snapshot.ContentType
		requestCtx["is_json"] = rd.Snapshot.IsJSON
		if rd.Snapshot.Body != nil {
			requestCtx["body"] = string(rd.Snapshot.Body)
		}
		if rd.Snapshot.BodyJSON != nil {
			requestCtx["body_json"] = rd.Snapshot.BodyJSON
		}
	} else {
		// Fall back to building from live request (no snapshot available)
		requestCtx["method"] = req.Method
		requestCtx["remote_addr"] = remoteAddr

		if req.URL != nil {
			requestCtx["url"] = req.URL.String()
			requestCtx["path"] = req.URL.Path
			requestCtx["query"] = req.URL.Query()
		} else {
			requestCtx["url"] = ""
			requestCtx["path"] = ""
			requestCtx["query"] = emptyQueryMap
		}

		if req.Header != nil {
			requestCtx["headers"] = rd.GetLowercaseHeaders(req.Header)
		} else {
			requestCtx["headers"] = emptyStringMap
		}
	}

	// Request-level metadata
	requestCtx["id"] = rd.ID
	requestCtx["data"] = rd.Data

	// Timing information
	if !rd.StartTime.IsZero() {
		requestCtx["start_time"] = rd.StartTime.Unix()
		requestCtx["start_time_ms"] = rd.StartTime.UnixMilli()
		requestCtx["start_time_rfc3339"] = rd.StartTime.Format(time.RFC3339)
		requestCtx["start_date"] = rd.StartTime.Format("2006-01-02")
		requestCtx["start_datetime"] = rd.StartTime.Format(time.DateTime)
	}

	// Cache status
	cacheStatus := "MISS"
	if rd.ResponseCacheHit {
		cacheStatus = "HIT"
	} else if rd.SignatureCacheHit {
		cacheStatus = "SIG_HIT"
	}
	requestCtx["cache_status"] = cacheStatus

	// --- New namespace: session ---
	sessionCtx := emptyAnyMap
	if rd.SessionCtx != nil {
		authData := map[string]any{
			"type": rd.SessionCtx.Auth.Type,
			"data": rd.SessionCtx.Auth.Data,
		}
		if rd.SessionCtx.Auth.Data == nil {
			authData["data"] = emptyAnyMap
		}
		sessionCtx = map[string]any{
			"id":   rd.SessionCtx.ID,
			"data": rd.SessionCtx.Data,
			"auth": authData,
		}
	} else if rd.SessionData != nil {
		sessionCtx = map[string]any{
			"id":   rd.SessionData.ID,
			"data": rd.SessionData.Data,
		}
		if rd.SessionData.AuthData != nil {
			sessionCtx["auth"] = map[string]any{
				"type": rd.SessionData.AuthData.Type,
				"data": rd.SessionData.AuthData.Data,
			}
		} else {
			sessionCtx["auth"] = map[string]any{"data": emptyAnyMap}
		}
	}

	// --- New namespace: client ---
	clientCtx := emptyAnyMap
	if rd.ClientCtx != nil {
		clientCtx = map[string]any{
			"ip": rd.ClientCtx.IP,
		}
		if rd.ClientCtx.Location != nil {
			clientCtx["location"] = map[string]any{
				"country":        rd.ClientCtx.Location.Country,
				"country_code":   rd.ClientCtx.Location.CountryCode,
				"continent":      rd.ClientCtx.Location.Continent,
				"continent_code": rd.ClientCtx.Location.ContinentCode,
				"asn":            rd.ClientCtx.Location.ASN,
				"as_name":        rd.ClientCtx.Location.ASName,
				"as_domain":      rd.ClientCtx.Location.ASDomain,
			}
		}
		if rd.ClientCtx.UserAgent != nil {
			clientCtx["user_agent"] = map[string]any{
				"family":        rd.ClientCtx.UserAgent.Family,
				"major":         rd.ClientCtx.UserAgent.Major,
				"minor":         rd.ClientCtx.UserAgent.Minor,
				"patch":         rd.ClientCtx.UserAgent.Patch,
				"os_family":     rd.ClientCtx.UserAgent.OSFamily,
				"os_major":      rd.ClientCtx.UserAgent.OSMajor,
				"os_minor":      rd.ClientCtx.UserAgent.OSMinor,
				"os_patch":      rd.ClientCtx.UserAgent.OSPatch,
				"device_family": rd.ClientCtx.UserAgent.DeviceFamily,
				"device_brand":  rd.ClientCtx.UserAgent.DeviceBrand,
				"device_model":  rd.ClientCtx.UserAgent.DeviceModel,
			}
		}
		if rd.ClientCtx.Fingerprint != nil {
			clientCtx["fingerprint"] = map[string]any{
				"hash":            rd.ClientCtx.Fingerprint.Hash,
				"composite":       rd.ClientCtx.Fingerprint.Composite,
				"ip_hash":         rd.ClientCtx.Fingerprint.IPHash,
				"user_agent_hash": rd.ClientCtx.Fingerprint.UserAgentHash,
				"header_pattern":  rd.ClientCtx.Fingerprint.HeaderPattern,
				"tls_hash":        rd.ClientCtx.Fingerprint.TLSHash,
				"cookie_count":    rd.ClientCtx.Fingerprint.CookieCount,
				"version":         rd.ClientCtx.Fingerprint.Version,
				"conn_duration":   rd.ClientCtx.Fingerprint.ConnDuration,
			}
		}
	}

	// --- New namespace: ctx (mutable per-request state + live request) ---
	ctxObj := make(map[string]any, 6)
	ctxObj["id"] = rd.ID
	ctxObj["data"] = rd.Data
	ctxObj["cache_status"] = cacheStatus

	// Build live request view for ctx.request
	liveReq := make(map[string]any, 6)
	liveReq["method"] = req.Method
	liveReq["remote_addr"] = remoteAddr
	if req.URL != nil {
		liveReq["url"] = req.URL.String()
		liveReq["path"] = req.URL.Path
		liveReq["query"] = req.URL.Query()
	} else {
		liveReq["url"] = ""
		liveReq["path"] = ""
		liveReq["query"] = emptyQueryMap
	}
	if req.Header != nil {
		liveReq["headers"] = rd.GetLowercaseHeaders(req.Header)
	} else {
		liveReq["headers"] = emptyStringMap
	}
	ctxObj["request"] = liveReq

	// Add timing information to ctx
	if !rd.StartTime.IsZero() {
		ctxObj["start_time"] = rd.StartTime.Unix()
		ctxObj["start_time_ms"] = rd.StartTime.UnixMilli()
		ctxObj["start_time_rfc3339"] = rd.StartTime.Format(time.RFC3339)
	}

	// ================================================================
	// Build final context with the 9-namespace model
	// ================================================================
	ctx := make(map[string]any, 21)

	// Expose secrets only via the top-level runtime secrets object.
	secretsCtx := emptyStringMap
	if rd.OriginCtx != nil && rd.OriginCtx.Secrets != nil {
		secretsCtx = rd.OriginCtx.Secrets
	} else if rd.Secrets != nil {
		secretsCtx = rd.Secrets
	}

	// 9-namespace model
	ctx["origin"] = originCtx
	ctx["server"] = serverCtx
	if varsCtx != nil {
		ctx["vars"] = varsCtx
	}
	ctx["features"] = featuresCtx
	ctx["request"] = requestCtx
	ctx["session"] = sessionCtx
	ctx["client"] = clientCtx
	ctx["ctx"] = ctxObj
	ctx["secrets"] = secretsCtx

	// Utility variables (top-level, not namespaced)
	now := time.Now()
	ctx["timestamp"] = now.Unix()
	ctx["timestamp_ms"] = now.UnixMilli()
	ctx["date"] = now.Format("2006-01-02")
	ctx["time"] = now.Format("15:04:05")
	ctx["datetime"] = now.Format(time.RFC3339)
	ctx["year"] = now.Year()
	ctx["month"] = int(now.Month())
	ctx["day"] = now.Day()
	ctx["uuid"] = rd.ID
	ctx["random"] = now.UnixNano() % 1000000

	// Lambda helpers for common operations.
	ctx["urlencode"] = func(text string, render func(string) (string, error)) (string, error) {
		rendered, err := render(text)
		if err != nil {
			return "", err
		}
		return url.QueryEscape(rendered), nil
	}
	ctx["pathencode"] = func(text string, render func(string) (string, error)) (string, error) {
		rendered, err := render(text)
		if err != nil {
			return "", err
		}
		return url.PathEscape(rendered), nil
	}

	return ctx
}

// AddLambdas adds common template helper lambdas to a context map.
// Call this when building custom template contexts outside of Resolve().
//
// Available lambdas:
//   - {{#urlencode}}...{{/urlencode}} - URL query encoding (spaces become +)
//   - {{#pathencode}}...{{/pathencode}} - URL path encoding (spaces become %20)
func AddLambdas(ctx map[string]any) {
	ctx["urlencode"] = func(text string, render func(string) (string, error)) (string, error) {
		rendered, err := render(text)
		if err != nil {
			return "", err
		}
		return url.QueryEscape(rendered), nil
	}
	ctx["pathencode"] = func(text string, render func(string) (string, error)) (string, error) {
		rendered, err := render(text)
		if err != nil {
			return "", err
		}
		return url.PathEscape(rendered), nil
	}
}

// ClearCache clears the template cache.
func ClearCache() {
	globalResolver.cache.Range(func(key, value any) bool {
		globalResolver.cache.Delete(key)
		return true
	})
}
