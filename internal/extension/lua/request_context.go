// Package lua provides Lua scripting support for dynamic request/response processing.
package lua

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/extension/scripting"
	lua "github.com/yuin/gopher-lua"
)

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

// RequestContext encapsulates all context data for a request
type RequestContext struct {
	req          *http.Request
	requestIP    string
	fingerprint  *reqctx.Fingerprint
	userAgent    *reqctx.UserAgent
	location     *reqctx.Location
	sessionData  *reqctx.SessionData
	contextData  map[string]any
	config       map[string]any
	original     *reqctx.OriginalRequestData
	variables    map[string]any
	secrets      map[string]string
	env          map[string]any
	featureFlags map[string]any

	// Bridge fields for new namespace model (populated alongside legacy fields)
	originCtx   *reqctx.OriginContext
	varsCtx     *reqctx.VarsContext
	featuresCtx *reqctx.FeaturesContext
	clientCtx   *reqctx.ClientContext
	ctxObj      *reqctx.CtxObject
	requestID   string
	startTime   time.Time
}

// NewRequestContext creates a new RequestContext from an HTTP request
func NewRequestContext(req *http.Request) *RequestContext {
	if req == nil {
		return &RequestContext{}
	}

	requestData := reqctx.GetRequestData(req.Context())

	// Extract client IP
	clientIP := getClientIP(req.RemoteAddr, req.Header)

	// Handle nil requestData
	if requestData == nil {
		return &RequestContext{
			req:       req,
			requestIP: clientIP,
		}
	}

	return &RequestContext{
		req:          req,
		requestIP:    clientIP,
		fingerprint:  requestData.Fingerprint,
		userAgent:    requestData.UserAgent,
		location:     requestData.Location,
		sessionData:  requestData.SessionData,
		contextData:  requestData.Data,
		config:       requestData.Config,
		original:     requestData.OriginalRequest,
		variables:    requestData.Variables,
		secrets:      requestData.Secrets,
		env:          requestData.Env,
		featureFlags: requestData.FeatureFlags,

		// Bridge fields
		originCtx:   requestData.OriginCtx,
		varsCtx:     requestData.VarsCtx,
		featuresCtx: requestData.FeaturesCtx,
		clientCtx:   requestData.ClientCtx,
		ctxObj:      requestData.CtxObj,
		requestID:   requestData.ID,
		startTime:   requestData.StartTime,
	}
}

// PopulateLuaState populates the Lua state with the 9-namespace context model.
func (rc *RequestContext) PopulateLuaState(L *lua.LState) {
	// origin - from OriginCtx
	L.SetGlobal("origin", rc.buildOriginTable(L))

	// secrets - top-level runtime alias for resolved origin secrets
	L.SetGlobal("secrets", rc.buildSecretsTable(L))

	// server - from serverVarsGetter
	if serverVarsGetter != nil {
		if serverVars := serverVarsGetter(); serverVars != nil {
			L.SetGlobal("server", convertMapToLuaTable(L, serverVars))
		} else {
			L.SetGlobal("server", L.NewTable())
		}
	} else {
		L.SetGlobal("server", L.NewTable())
	}

	// vars - from VarsCtx.Data
	if rc.varsCtx != nil && rc.varsCtx.Data != nil {
		L.SetGlobal("vars", convertMapToLuaTable(L, rc.varsCtx.Data))
	} else {
		L.SetGlobal("vars", L.NewTable())
	}

	// features - from FeaturesCtx.Data
	if rc.featuresCtx != nil && rc.featuresCtx.Data != nil {
		L.SetGlobal("features", convertMapToLuaTable(L, rc.featuresCtx.Data))
	} else {
		L.SetGlobal("features", L.NewTable())
	}

	// request - immutable snapshot (not set here; available via request table in scripts)

	// session - from SessionData
	if rc.sessionData != nil {
		L.SetGlobal("session", createSessionTable(L, rc.sessionData))
	} else {
		L.SetGlobal("session", L.NewTable())
	}

	// client - from ClientCtx
	L.SetGlobal("client", rc.buildClientTable(L))

	// ctx - per-request mutable state
	L.SetGlobal("ctx", rc.buildCtxTable(L))

	// cache - reserved for future use
}

// buildOriginTable creates the "origin" namespace table from OriginCtx.
func (rc *RequestContext) buildOriginTable(L *lua.LState) *lua.LTable {
	table := L.NewTable()
	if rc.originCtx == nil {
		return table
	}
	oc := rc.originCtx

	table.RawSetString("id", lua.LString(oc.ID))
	table.RawSetString("hostname", lua.LString(oc.Hostname))
	table.RawSetString("workspace_id", lua.LString(oc.WorkspaceID))
	table.RawSetString("environment", lua.LString(oc.Environment))
	table.RawSetString("version", lua.LString(oc.Version))
	table.RawSetString("revision", lua.LString(oc.Revision))
	table.RawSetString("name", lua.LString(oc.Name))
	table.RawSetString("config_mode", lua.LString(oc.ConfigMode))
	table.RawSetString("config_reason", lua.LString(oc.ConfigReason))

	// Tags as array table
	tagsTable := L.NewTable()
	for _, tag := range oc.Tags {
		tagsTable.Append(lua.LString(tag))
	}
	table.RawSetString("tags", tagsTable)

	// Params (on_load callback data)
	if oc.Params != nil {
		table.RawSetString("params", convertMapToLuaTable(L, oc.Params))
	} else {
		table.RawSetString("params", L.NewTable())
	}

	return table
}

func (rc *RequestContext) buildSecretsTable(L *lua.LState) *lua.LTable {
	secretsTable := L.NewTable()

	var secrets map[string]string
	switch {
	case rc.originCtx != nil && rc.originCtx.Secrets != nil:
		secrets = rc.originCtx.Secrets
	case rc.secrets != nil:
		secrets = rc.secrets
	}

	for k, v := range secrets {
		secretsTable.RawSetString(k, lua.LString(v))
	}

	return secretsTable
}

// buildClientTable creates the "client" namespace table from ClientCtx.
func (rc *RequestContext) buildClientTable(L *lua.LState) *lua.LTable {
	table := L.NewTable()
	if rc.clientCtx == nil {
		// Fallback: populate from legacy fields
		table.RawSetString("ip", lua.LString(rc.requestIP))
		if rc.location != nil {
			table.RawSetString("location", createLocationTable(L, rc.location))
		} else {
			table.RawSetString("location", L.NewTable())
		}
		if rc.userAgent != nil {
			table.RawSetString("user_agent", createUserAgentTable(L, rc.userAgent))
		} else {
			table.RawSetString("user_agent", L.NewTable())
		}
		if rc.fingerprint != nil {
			table.RawSetString("fingerprint", createFingerprintTable(L, rc.fingerprint))
		} else {
			table.RawSetString("fingerprint", L.NewTable())
		}
		return table
	}

	cc := rc.clientCtx
	table.RawSetString("ip", lua.LString(cc.IP))

	if cc.Location != nil {
		table.RawSetString("location", createLocationTable(L, cc.Location))
	} else {
		table.RawSetString("location", L.NewTable())
	}

	if cc.UserAgent != nil {
		table.RawSetString("user_agent", createUserAgentTable(L, cc.UserAgent))
	} else {
		table.RawSetString("user_agent", L.NewTable())
	}

	if cc.Fingerprint != nil {
		table.RawSetString("fingerprint", createFingerprintTable(L, cc.Fingerprint))
	} else {
		table.RawSetString("fingerprint", L.NewTable())
	}

	return table
}

// buildCtxTable creates the "ctx" namespace table from CtxObj or legacy fields.
func (rc *RequestContext) buildCtxTable(L *lua.LState) *lua.LTable {
	table := L.NewTable()

	if rc.ctxObj != nil {
		table.RawSetString("id", lua.LString(rc.ctxObj.ID))
		table.RawSetString("cache_status", lua.LString(rc.ctxObj.CacheStatus))
		if !rc.ctxObj.StartTime.IsZero() {
			table.RawSetString("start_time", lua.LString(rc.ctxObj.StartTime.Format(time.RFC3339)))
		} else {
			table.RawSetString("start_time", lua.LString(""))
		}
		if rc.ctxObj.Data != nil {
			table.RawSetString("data", convertMapToLuaTable(L, rc.ctxObj.Data))
		} else {
			table.RawSetString("data", L.NewTable())
		}
	} else {
		// Fallback: populate from legacy fields
		table.RawSetString("id", lua.LString(rc.requestID))
		table.RawSetString("cache_status", lua.LString(""))
		if !rc.startTime.IsZero() {
			table.RawSetString("start_time", lua.LString(rc.startTime.Format(time.RFC3339)))
		} else {
			table.RawSetString("start_time", lua.LString(""))
		}
		if rc.contextData != nil {
			table.RawSetString("data", convertMapToLuaTable(L, rc.contextData))
		} else {
			table.RawSetString("data", L.NewTable())
		}
	}

	return table
}

// createFingerprintTable creates a Lua table from fingerprint data
func createFingerprintTable(L *lua.LState, fp *reqctx.Fingerprint) *lua.LTable {
	table := L.NewTable()

	table.RawSetString("hash", lua.LString(fp.Hash))
	table.RawSetString("composite", lua.LString(fp.Composite))
	table.RawSetString("ip_hash", lua.LString(fp.IPHash))
	table.RawSetString("user_agent_hash", lua.LString(fp.UserAgentHash))
	table.RawSetString("header_pattern", lua.LString(fp.HeaderPattern))
	table.RawSetString("tls_hash", lua.LString(fp.TLSHash))
	table.RawSetString("cookie_count", lua.LNumber(fp.CookieCount))
	table.RawSetString("conn_duration_ms", lua.LNumber(fp.ConnDuration.Milliseconds()))
	table.RawSetString("version", lua.LString(fp.Version))

	return table
}

// createUserAgentTable creates a Lua table from user agent data
func createUserAgentTable(L *lua.LState, ua *reqctx.UserAgent) *lua.LTable {
	table := L.NewTable()

	table.RawSetString("family", lua.LString(ua.Family))
	table.RawSetString("major", lua.LString(ua.Major))
	table.RawSetString("minor", lua.LString(ua.Minor))
	table.RawSetString("patch", lua.LString(ua.Patch))
	table.RawSetString("os_family", lua.LString(ua.OSFamily))
	table.RawSetString("os_major", lua.LString(ua.OSMajor))
	table.RawSetString("os_minor", lua.LString(ua.OSMinor))
	table.RawSetString("os_patch", lua.LString(ua.OSPatch))
	table.RawSetString("device_family", lua.LString(ua.DeviceFamily))
	table.RawSetString("device_brand", lua.LString(ua.DeviceBrand))
	table.RawSetString("device_model", lua.LString(ua.DeviceModel))

	return table
}

// createLocationTable creates a Lua table from Location data
// Always returns a non-nil table to avoid nil checks
func createLocationTable(L *lua.LState, loc *reqctx.Location) *lua.LTable {
	table := L.NewTable()

	if loc != nil {
		table.RawSetString("country", lua.LString(loc.Country))
		table.RawSetString("country_code", lua.LString(loc.CountryCode))
		table.RawSetString("continent", lua.LString(loc.Continent))
		table.RawSetString("continent_code", lua.LString(loc.ContinentCode))
		table.RawSetString("asn", lua.LString(loc.ASN))
		table.RawSetString("as_name", lua.LString(loc.ASName))
		table.RawSetString("as_domain", lua.LString(loc.ASDomain))
	}

	return table
}

// createSessionTable creates a Lua table from session data
func createSessionTable(L *lua.LState, sessionData interface{}) *lua.LTable {
	table := L.NewTable()

	if sessionData == nil {
		return table
	}

	// Use reflection to extract session data fields
	v := reflect.ValueOf(sessionData)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return table
	}

	// Extract common session fields
	if idField := v.FieldByName("ID"); idField.IsValid() && idField.Kind() == reflect.String {
		table.RawSetString("id", lua.LString(idField.String()))
	}

	if expiresField := v.FieldByName("Expires"); expiresField.IsValid() {
		table.RawSetString("expires", lua.LString(expiresField.String()))
	}

	// Extract is_authenticated from AuthData presence
	if authDataField := v.FieldByName("AuthData"); authDataField.IsValid() && !authDataField.IsZero() {
		table.RawSetString("is_authenticated", lua.LBool(true))

		// Create auth table with type, data object, and all data fields directly accessible
		authTable := L.NewTable()

		if authDataField.Kind() == reflect.Ptr {
			authDataField = authDataField.Elem()
		}

		if authDataField.Kind() == reflect.Struct {
			// Auth type
			if typeField := authDataField.FieldByName("Type"); typeField.IsValid() && typeField.Kind() == reflect.String {
				authTable.RawSetString("type", lua.LString(typeField.String()))
			}

			// Auth data (enriched by callbacks) - add as nested object and also merge directly
			if dataField := authDataField.FieldByName("Data"); dataField.IsValid() && !dataField.IsZero() {
				if dataField.Kind() == reflect.Map {
					// Add data as nested table
					dataTable := convertMapToLuaTable(L, dataField.Interface())
					authTable.RawSetString("data", dataTable)

					// Also merge all fields directly into auth table for convenience
					dataMap := dataField.Interface().(map[string]any)
					for k, v := range dataMap {
						authTable.RawSetString(k, convertInterfaceToLua(L, v))
					}
				}
			}
		}

		table.RawSetString("auth", authTable)
	} else {
		table.RawSetString("is_authenticated", lua.LBool(false))
	}

	// Extract custom data (from session callbacks)
	if dataField := v.FieldByName("Data"); dataField.IsValid() && !dataField.IsZero() {
		if dataField.Kind() == reflect.Map {
			dataTable := convertMapToLuaTable(L, dataField.Interface())
			table.RawSetString("data", dataTable)
		}
	}

	// Extract visited URLs
	if visitedField := v.FieldByName("Visited"); visitedField.IsValid() && visitedField.Kind() == reflect.Slice {
		visitedTable := L.NewTable()
		for i := 0; i < visitedField.Len(); i++ {
			visitedTable.Append(convertValueToLua(L, visitedField.Index(i)))
		}
		table.RawSetString("visited", visitedTable)
	}

	// Extract visited and cookie counts
	if visitedField := v.FieldByName("VisitedCount"); visitedField.IsValid() && visitedField.Kind() == reflect.Int {
		table.RawSetString("visited_count", lua.LNumber(visitedField.Int()))
	}

	if cookieCountField := v.FieldByName("CookieCount"); cookieCountField.IsValid() && cookieCountField.Kind() == reflect.Int {
		table.RawSetString("cookie_count", lua.LNumber(cookieCountField.Int()))
	}

	return table
}

// convertMapToLuaTable converts a Go map[string]any to a Lua table
func convertMapToLuaTable(L *lua.LState, data interface{}) *lua.LTable {
	table := L.NewTable()

	if data == nil {
		return table
	}

	dataMap, ok := data.(map[string]any)
	if !ok {
		return table
	}

	for key, value := range dataMap {
		luaValue := convertInterfaceToLua(L, value)
		table.RawSetString(key, luaValue)
	}

	return table
}

// convertToLuaValue is an alias for convertInterfaceToLua
// Used for exposing context data (including config params) to Lua scripts
func convertToLuaValue(L *lua.LState, value interface{}) lua.LValue {
	return convertInterfaceToLua(L, value)
}

// convertInterfaceToLua converts a Go interface{} to a Lua value
func convertInterfaceToLua(L *lua.LState, value interface{}) lua.LValue {
	if value == nil {
		return lua.LNil
	}

	switch v := value.(type) {
	case string:
		return lua.LString(v)
	case int:
		return lua.LNumber(v)
	case int64:
		return lua.LNumber(v)
	case float64:
		return lua.LNumber(v)
	case bool:
		return lua.LBool(v)
	case map[string]any:
		return convertMapToLuaTable(L, v)
	case []interface{}:
		arrayTable := L.NewTable()
		for _, item := range v {
			arrayTable.Append(convertInterfaceToLua(L, item))
		}
		return arrayTable
	case []string:
		arrayTable := L.NewTable()
		for _, item := range v {
			arrayTable.Append(lua.LString(item))
		}
		return arrayTable
	default:
		// Try reflection as fallback
		rv := reflect.ValueOf(value)
		return convertValueToLua(L, rv)
	}
}

// convertValueToLua converts a Go reflect.Value to a Lua value
func convertValueToLua(L *lua.LState, v reflect.Value) lua.LValue {
	if !v.IsValid() {
		return lua.LNil
	}

	switch v.Kind() {
	case reflect.String:
		return lua.LString(v.String())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return lua.LNumber(v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return lua.LNumber(v.Uint())
	case reflect.Float32, reflect.Float64:
		return lua.LNumber(v.Float())
	case reflect.Bool:
		return lua.LBool(v.Bool())
	case reflect.Map:
		if v.Type().Key().Kind() == reflect.String {
			return convertMapToLuaTable(L, v.Interface())
		}
		return lua.LNil
	case reflect.Slice, reflect.Array:
		arrayTable := L.NewTable()
		for i := 0; i < v.Len(); i++ {
			arrayTable.Append(convertValueToLua(L, v.Index(i)))
		}
		return arrayTable
	case reflect.Ptr:
		if v.IsNil() {
			return lua.LNil
		}
		return convertValueToLua(L, v.Elem())
	case reflect.Interface:
		if v.IsNil() {
			return lua.LNil
		}
		return convertInterfaceToLua(L, v.Interface())
	default:
		return lua.LString(fmt.Sprintf("%v", v.Interface()))
	}
}

// getClientIP extracts the client IP from the request
// It checks X-Real-IP, X-Forwarded-For, and RemoteAddr in that order
func getClientIP(remoteAddr string, headers http.Header) string {
	// Check X-Real-IP header first (highest precedence)
	if xri := headers.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Check X-Forwarded-For header (first IP in the list)
	if xff := headers.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Use RemoteAddr (extract IP from "host:port" format)
	if remoteAddr != "" {
		host, _, err := net.SplitHostPort(remoteAddr)
		if err == nil {
			return host
		}
		// If SplitHostPort fails, try to use RemoteAddr as-is (might be just IP)
		return remoteAddr
	}

	return ""
}

// BuildContextTable creates a unified Lua context table from RequestContext
// This table contains all context data needed for scripts (matchers, modifiers, etc.)
func (rc *RequestContext) BuildContextTable(L *lua.LState) *lua.LTable {
	if rc == nil {
		return L.NewTable()
	}

	// Convert RequestContext to ScriptContext
	serverVars := make(map[string]any)
	if serverVarsGetter != nil {
		serverVars = serverVarsGetter()
	}

	sc := &scripting.ScriptContext{
		RequestIP:    rc.requestIP,
		Location:     rc.location,
		UserAgent:    rc.userAgent,
		Fingerprint:  rc.fingerprint,
		SessionData:  rc.sessionData,
		Config:       rc.config,
		RequestData:  rc.contextData,
		Variables:    rc.variables,
		Secrets:      rc.secrets,
		Env:          rc.env,
		FeatureFlags: rc.featureFlags,
		ServerVars:   serverVars,
	}

	// Extract request info
	if rc.req != nil {
		reqInfo := &scripting.RequestInfo{
			Method:  rc.req.Method,
			Path:    rc.req.URL.Path,
			Host:    rc.req.Host,
			Headers: make(map[string]string),
			Query:   make(map[string]string),
		}

		// Store headers under lowercase keys only (single entry per header).
		// Lua scripts use: req.headers["content-type"], req.headers["x-admin"]
		for k, v := range rc.req.Header {
			if len(v) > 0 {
				reqInfo.Headers[strings.ToLower(k)] = v[0]
			}
		}

		// Extract query params
		for k, v := range rc.req.URL.Query() {
			if len(v) > 0 {
				reqInfo.Query[k] = v[0]
			}
		}

		sc.Request = reqInfo
	}

	// Build and return the Lua context table
	return scripting.BuildContextTable(L, sc)
}
