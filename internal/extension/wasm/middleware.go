package wasm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// Middleware runs WASM plugins as HTTP middleware.
type Middleware struct {
	runtime *Runtime
	plugins []*Plugin
}

// NewMiddleware creates a new WASM middleware with the given runtime and plugins.
func NewMiddleware(runtime *Runtime, plugins []*Plugin) *Middleware {
	return &Middleware{
		runtime: runtime,
		plugins: plugins,
	}
}

// HandleRequest returns an http.Handler that runs request-phase WASM plugins
// before passing the request to the next handler.
func (m *Middleware) HandleRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		var allOriginSecrets map[string]string

		// Build the request context for plugins
		rc := NewRequestContext()

		// Populate request metadata
		rc.mu.Lock()
		rc.RequestMethod = r.Method
		rc.RequestPath = r.URL.Path
		rc.ClientIP = r.RemoteAddr
		for key, values := range r.URL.Query() {
			if len(values) > 0 {
				rc.QueryParams[key] = values[0]
			}
		}
		rc.mu.Unlock()

		// Store request headers under lowercase keys only (single entry per header).
		// WASM plugins use: sb_get_request_header("content-type")
		for name, values := range r.Header {
			if len(values) > 0 {
				rc.SetRequestHeader(strings.ToLower(name), values[0])
			}
		}

		// Read request body if present
		if r.Body != nil {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				slog.ErrorContext(ctx, "wasm middleware: failed to read request body", "error", err)
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			r.Body.Close()
			rc.SetRequestBody(body)
			// Restore body for downstream handlers
			r.Body = io.NopCloser(bytes.NewReader(body))
		}

		// Populate new context model fields from RequestData bridge fields
		if rd := reqctx.GetRequestData(ctx); rd != nil {
			allOriginSecrets = extractOriginSecrets(rd)
			rc.mu.Lock()
			if rd.OriginCtx != nil {
				rc.OriginID = rd.OriginCtx.ID
				rc.OriginParams = stringifyMap(rd.OriginCtx.Params)
				rc.OriginMeta = originToStringMap(rd.OriginCtx)
			}
			if rd.ServerCtx != nil {
				rc.ServerVars = stringifyMap(rd.ServerCtx.ToMap())
			}
			if rd.VarsCtx != nil {
				rc.Vars = stringifyMap(rd.VarsCtx.Data)
			}
			if rd.FeaturesCtx != nil {
				rc.Features = stringifyMap(rd.FeaturesCtx.Data)
			}
			if rd.SessionCtx != nil {
				rc.SessionData = stringifyMap(rd.SessionCtx.Data)
				rc.AuthInfo = buildAuthMap(rd.SessionCtx.Auth)
				rc.AuthJSON = marshalAuthJSON(rd.SessionCtx.Auth)
			} else if rd.SessionData != nil && rd.SessionData.AuthData != nil {
				// Fallback to legacy SessionData.AuthData
				auth := reqctx.SessionAuth{
					Type: rd.SessionData.AuthData.Type,
					Data: rd.SessionData.AuthData.Data,
				}
				rc.AuthInfo = buildAuthMap(auth)
				rc.AuthJSON = marshalAuthJSON(auth)
			}
			if rd.ClientCtx != nil {
				rc.ClientLocation = locationToStringMap(rd.ClientCtx.Location)
				rc.ClientUserAgent = userAgentToStringMap(rd.ClientCtx.UserAgent)
				rc.ClientFingerprint = fingerprintToStringMap(rd.ClientCtx.Fingerprint)
			} else {
				// Fallback to top-level RequestData fields
				rc.ClientLocation = locationToStringMap(rd.Location)
				rc.ClientUserAgent = userAgentToStringMap(rd.UserAgent)
				rc.ClientFingerprint = fingerprintToStringMap(rd.Fingerprint)
			}
			if rd.CtxObj != nil {
				rc.CtxScalars = ctxToStringMap(rd.CtxObj)
				rc.CtxData = stringifyMapToString(rd.CtxObj.Data)
			}
			rc.mu.Unlock()
		}

		// Attach request context
		ctx = WithRequestContext(ctx, rc)

		// Run request-phase plugins
		for _, plugin := range m.plugins {
			if plugin.Phase() != PhaseRequest {
				continue
			}

			// Set plugin config
			rc.mu.Lock()
			rc.PluginConfig = plugin.config
			rc.OriginSecrets = filterOriginSecrets(allOriginSecrets, plugin.allowedSecrets)
			rc.mu.Unlock()

			action, err := plugin.CallOnRequest(ctx)
			if err != nil {
				slog.ErrorContext(ctx, "wasm plugin request phase error",
					"plugin", plugin.Name(),
					"error", err,
				)
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}

			if action == ActionBlock {
				slog.InfoContext(ctx, "wasm plugin blocked request",
					"plugin", plugin.Name(),
				)
				http.Error(w, "blocked by plugin", http.StatusForbidden)
				return
			}
		}

		// Write back ctx.data changes to RequestData so downstream handlers see them
		if rd := reqctx.GetRequestData(ctx); rd != nil && rd.CtxObj != nil {
			rc.mu.RLock()
			if len(rc.CtxData) > 0 {
				if rd.CtxObj.Data == nil {
					rd.CtxObj.Data = make(map[string]any, len(rc.CtxData))
				}
				for k, v := range rc.CtxData {
					rd.CtxObj.Data[k] = v
				}
			}
			rc.mu.RUnlock()
		}

		// Check if a plugin wants to send a custom response
		rc.mu.RLock()
		if rc.SendResponse {
			code := rc.SendResponseCode
			hdrs := rc.SendResponseHeaders
			body := rc.SendResponseBody
			rc.mu.RUnlock()

			for k, v := range hdrs {
				w.Header().Set(k, v)
			}
			if w.Header().Get("Content-Length") == "" && len(body) > 0 {
				w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			}
			w.WriteHeader(code)
			if len(body) > 0 {
				w.Write(body) //nolint:errcheck
			}
			return
		}
		rc.mu.RUnlock()

		// Apply any header modifications from plugins back to the request
		rc.mu.RLock()
		for name, value := range rc.RequestHeaders {
			r.Header.Set(name, value)
		}
		modifiedBody := rc.RequestBody
		modifiedPath := rc.RequestPath
		modifiedMethod := rc.RequestMethod
		rc.mu.RUnlock()

		// Apply path/method modifications
		if modifiedPath != "" && modifiedPath != r.URL.Path {
			r.URL.Path = modifiedPath
		}
		if modifiedMethod != "" && modifiedMethod != r.Method {
			r.Method = modifiedMethod
		}

		// If plugins modified the body, update the request
		if modifiedBody != nil {
			r.Body = io.NopCloser(bytes.NewReader(modifiedBody))
			r.ContentLength = int64(len(modifiedBody))
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// HandleResponse runs response-phase WASM plugins on an HTTP response.
// This is intended to be called after the upstream response is received.
func (m *Middleware) HandleResponse(resp *http.Response) error {
	if resp == nil {
		return nil
	}

	ctx := resp.Request.Context()
	rc := RequestContextFromContext(ctx)
	if rc == nil {
		rc = NewRequestContext()
		ctx = WithRequestContext(ctx, rc)
	}
	var allOriginSecrets map[string]string
	if rd := reqctx.GetRequestData(ctx); rd != nil {
		allOriginSecrets = extractOriginSecrets(rd)
	}

	// Copy response headers into context
	for name, values := range resp.Header {
		if len(values) > 0 {
			rc.SetResponseHeader(name, values[0])
		}
	}

	// Read response body
	if resp.Body != nil {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		resp.Body.Close()
		rc.SetResponseBody(body)
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}

	// Run response-phase plugins
	for _, plugin := range m.plugins {
		if plugin.Phase() != PhaseResponse {
			continue
		}

		rc.mu.Lock()
		rc.PluginConfig = plugin.config
		rc.OriginSecrets = filterOriginSecrets(allOriginSecrets, plugin.allowedSecrets)
		rc.mu.Unlock()

		action, err := plugin.CallOnResponse(ctx)
		if err != nil {
			slog.ErrorContext(ctx, "wasm plugin response phase error",
				"plugin", plugin.Name(),
				"error", err,
			)
			return err
		}

		if action == ActionBlock {
			slog.InfoContext(ctx, "wasm plugin blocked response",
				"plugin", plugin.Name(),
			)
			resp.StatusCode = http.StatusForbidden
			resp.Body = io.NopCloser(bytes.NewReader([]byte("blocked by plugin")))
			return nil
		}
	}

	// Apply modifications back to the response
	rc.mu.RLock()
	for name, value := range rc.ResponseHeaders {
		resp.Header.Set(name, value)
	}
	modifiedBody := rc.ResponseBody
	rc.mu.RUnlock()

	if modifiedBody != nil {
		resp.Body = io.NopCloser(bytes.NewReader(modifiedBody))
		resp.ContentLength = int64(len(modifiedBody))
	}

	return nil
}

// stringifyMap converts a map[string]any to map[string]string for WASM consumption.
func stringifyMap(m map[string]any) map[string]string {
	if m == nil {
		return nil
	}
	result := make(map[string]string, len(m))
	for k, v := range m {
		result[k] = fmt.Sprintf("%v", v)
	}
	return result
}

func extractOriginSecrets(rd *reqctx.RequestData) map[string]string {
	if rd == nil {
		return nil
	}
	if rd.OriginCtx != nil && rd.OriginCtx.Secrets != nil {
		return rd.OriginCtx.Secrets
	}
	if rd.Secrets != nil {
		return rd.Secrets
	}
	return nil
}

// buildAuthMap creates a flat string map from auth data, including type and is_authenticated.
func buildAuthMap(auth reqctx.SessionAuth) map[string]string {
	m := make(map[string]string, len(auth.Data)+2)
	m["type"] = auth.Type
	if auth.Type != "" {
		m["is_authenticated"] = "true"
	} else {
		m["is_authenticated"] = "false"
	}
	for k, v := range auth.Data {
		m[k] = fmt.Sprintf("%v", v)
	}
	return m
}

// marshalAuthJSON serializes the auth object to JSON bytes.
func marshalAuthJSON(auth reqctx.SessionAuth) []byte {
	data, err := json.Marshal(auth)
	if err != nil {
		return nil
	}
	return data
}

// locationToStringMap converts a Location struct to a flat string map.
func locationToStringMap(loc *reqctx.Location) map[string]string {
	if loc == nil {
		return nil
	}
	return map[string]string{
		"country":        loc.Country,
		"country_code":   loc.CountryCode,
		"continent":      loc.Continent,
		"continent_code": loc.ContinentCode,
		"asn":            loc.ASN,
		"as_name":        loc.ASName,
		"as_domain":      loc.ASDomain,
	}
}

// userAgentToStringMap converts a UserAgent struct to a flat string map.
func userAgentToStringMap(ua *reqctx.UserAgent) map[string]string {
	if ua == nil {
		return nil
	}
	return map[string]string{
		"family":        ua.Family,
		"major":         ua.Major,
		"minor":         ua.Minor,
		"patch":         ua.Patch,
		"os_family":     ua.OSFamily,
		"os_major":      ua.OSMajor,
		"os_minor":      ua.OSMinor,
		"os_patch":      ua.OSPatch,
		"device_family": ua.DeviceFamily,
		"device_brand":  ua.DeviceBrand,
		"device_model":  ua.DeviceModel,
	}
}

// fingerprintToStringMap converts a Fingerprint struct to a flat string map.
func fingerprintToStringMap(fp *reqctx.Fingerprint) map[string]string {
	if fp == nil {
		return nil
	}
	return map[string]string{
		"hash":             fp.Hash,
		"composite":        fp.Composite,
		"ip_hash":          fp.IPHash,
		"user_agent_hash":  fp.UserAgentHash,
		"header_pattern":   fp.HeaderPattern,
		"tls_hash":         fp.TLSHash,
		"cookie_count":     strconv.Itoa(fp.CookieCount),
		"version":          fp.Version,
		"conn_duration_ms": strconv.FormatInt(fp.ConnDuration.Milliseconds(), 10),
	}
}

// originToStringMap converts an OriginContext to a flat metadata string map.
func originToStringMap(oc *reqctx.OriginContext) map[string]string {
	if oc == nil {
		return nil
	}
	return map[string]string{
		"hostname":     oc.Hostname,
		"workspace_id": oc.WorkspaceID,
		"environment":  oc.Environment,
		"version":      oc.Version,
		"name":         oc.Name,
		"revision":     oc.Revision,
		"config_mode":  oc.ConfigMode,
		"tags":         strings.Join(oc.Tags, ","),
	}
}

// ctxToStringMap converts CtxObject scalar fields to a flat string map.
func ctxToStringMap(co *reqctx.CtxObject) map[string]string {
	if co == nil {
		return nil
	}
	return map[string]string{
		"id":           co.ID,
		"cache_status": co.CacheStatus,
		"debug":        strconv.FormatBool(co.Debug),
		"no_cache":     strconv.FormatBool(co.NoCache),
	}
}

// stringifyMapToString converts map[string]any to map[string]string.
func stringifyMapToString(m map[string]any) map[string]string {
	if m == nil {
		return nil
	}
	result := make(map[string]string, len(m))
	for k, v := range m {
		result[k] = fmt.Sprintf("%v", v)
	}
	return result
}

func filterOriginSecrets(all map[string]string, allowed []string) map[string]string {
	filtered := make(map[string]string)
	if len(all) == 0 || len(allowed) == 0 {
		return filtered
	}

	allowAll := false
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		if name == "*" {
			allowAll = true
			break
		}
		allowedSet[name] = struct{}{}
	}

	if allowAll {
		for k, v := range all {
			filtered[k] = v
		}
		return filtered
	}

	for name := range allowedSet {
		if value, ok := all[name]; ok {
			filtered[name] = value
		}
	}

	return filtered
}
