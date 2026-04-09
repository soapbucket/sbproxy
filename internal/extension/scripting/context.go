// Package scripting provides shared context types for Lua script execution across proxy components.
package scripting

import (
	"net/http"
	"reflect"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	lua "github.com/yuin/gopher-lua"
)

// ScriptContext represents all context data available to scripts
type ScriptContext struct {
	// Identity
	RequestIP string

	// GeoIP
	Location *reqctx.Location

	// Device
	UserAgent   *reqctx.UserAgent
	Fingerprint *reqctx.Fingerprint

	// Auth/Session
	SessionData *reqctx.SessionData

	// Config
	Config       map[string]any
	RequestData  map[string]any // Data from on_request callback results
	Variables    map[string]any // User-defined KV (workspace variables)
	Secrets      map[string]string
	Env          map[string]any // Per-origin env variables
	FeatureFlags map[string]any // Workspace feature flags
	ServerVars   map[string]any // Server-level variables

	// Request (always present)
	Request *RequestInfo

	// Response phase only (nil in request phase)
	ResponseStatus  *int
	ResponseHeaders map[string]string
}

// RequestInfo represents basic HTTP request information
type RequestInfo struct {
	Method  string
	Path    string
	Host    string
	Headers map[string]string
	Query   map[string]string
}

// BuildContextTable creates a unified Lua context table from ScriptContext
// This is the single `ctx` table available to all scripts
func BuildContextTable(L *lua.LState, sc *ScriptContext) *lua.LTable {
	if sc == nil {
		return L.NewTable()
	}

	ctx := L.NewTable()

	// Identity
	ctx.RawSetString("request_ip", lua.LString(sc.RequestIP))

	// GeoIP (location)
	locationTable := L.NewTable()
	if sc.Location != nil {
		locationTable.RawSetString("country", lua.LString(sc.Location.Country))
		locationTable.RawSetString("country_code", lua.LString(sc.Location.CountryCode))
		locationTable.RawSetString("continent", lua.LString(sc.Location.Continent))
		locationTable.RawSetString("continent_code", lua.LString(sc.Location.ContinentCode))
		locationTable.RawSetString("asn", lua.LString(sc.Location.ASN))
		locationTable.RawSetString("as_name", lua.LString(sc.Location.ASName))
		locationTable.RawSetString("as_domain", lua.LString(sc.Location.ASDomain))
	}
	ctx.RawSetString("location", locationTable)

	// Device (user_agent)
	userAgentTable := L.NewTable()
	if sc.UserAgent != nil {
		userAgentTable.RawSetString("family", lua.LString(sc.UserAgent.Family))
		userAgentTable.RawSetString("major", lua.LString(sc.UserAgent.Major))
		userAgentTable.RawSetString("minor", lua.LString(sc.UserAgent.Minor))
		userAgentTable.RawSetString("patch", lua.LString(sc.UserAgent.Patch))
		userAgentTable.RawSetString("os_family", lua.LString(sc.UserAgent.OSFamily))
		userAgentTable.RawSetString("os_major", lua.LString(sc.UserAgent.OSMajor))
		userAgentTable.RawSetString("os_minor", lua.LString(sc.UserAgent.OSMinor))
		userAgentTable.RawSetString("os_patch", lua.LString(sc.UserAgent.OSPatch))
		userAgentTable.RawSetString("device_family", lua.LString(sc.UserAgent.DeviceFamily))
		userAgentTable.RawSetString("device_brand", lua.LString(sc.UserAgent.DeviceBrand))
		userAgentTable.RawSetString("device_model", lua.LString(sc.UserAgent.DeviceModel))
	}
	ctx.RawSetString("user_agent", userAgentTable)

	// Fingerprint
	fingerprintTable := L.NewTable()
	if sc.Fingerprint != nil {
		fingerprintTable.RawSetString("hash", lua.LString(sc.Fingerprint.Hash))
		fingerprintTable.RawSetString("composite", lua.LString(sc.Fingerprint.Composite))
		fingerprintTable.RawSetString("ip_hash", lua.LString(sc.Fingerprint.IPHash))
		fingerprintTable.RawSetString("user_agent_hash", lua.LString(sc.Fingerprint.UserAgentHash))
		fingerprintTable.RawSetString("header_pattern", lua.LString(sc.Fingerprint.HeaderPattern))
		fingerprintTable.RawSetString("tls_hash", lua.LString(sc.Fingerprint.TLSHash))
		fingerprintTable.RawSetString("cookie_count", lua.LNumber(sc.Fingerprint.CookieCount))
		fingerprintTable.RawSetString("conn_duration_ms", lua.LNumber(sc.Fingerprint.ConnDuration.Milliseconds()))
		fingerprintTable.RawSetString("version", lua.LString(sc.Fingerprint.Version))
	}
	ctx.RawSetString("fingerprint", fingerprintTable)

	// Session/Auth
	sessionTable := L.NewTable()
	if sc.SessionData != nil {
		sessionTable.RawSetString("id", lua.LString(getSessionField(sc.SessionData, "ID")))
		sessionTable.RawSetString("expires", lua.LString(getSessionField(sc.SessionData, "Expires")))

		// is_authenticated
		hasAuth := !isSessionFieldZero(sc.SessionData, "AuthData")
		sessionTable.RawSetString("is_authenticated", lua.LBool(hasAuth))

		// Auth table
		authTable := L.NewTable()
		if hasAuth {
			authType := getSessionAuthField(sc.SessionData, "Type")
			authTable.RawSetString("type", lua.LString(authType))

			authDataMap := getSessionAuthDataMap(sc.SessionData)
			authTable.RawSetString("data", convertMapToLua(L, authDataMap))
		} else {
			authTable.RawSetString("data", L.NewTable())
		}
		sessionTable.RawSetString("auth", authTable)

		// Custom data
		dataMap := getSessionDataMap(sc.SessionData)
		sessionTable.RawSetString("data", convertMapToLua(L, dataMap))

		// Visited URLs and counts
		visitedURLs := getSessionVisited(sc.SessionData)
		sessionTable.RawSetString("visited", convertSliceToLua(L, visitedURLs))

		visitedCount := getSessionIntField(sc.SessionData, "VisitedCount")
		sessionTable.RawSetString("visited_count", lua.LNumber(visitedCount))

		cookieCount := getSessionIntField(sc.SessionData, "CookieCount")
		sessionTable.RawSetString("cookie_count", lua.LNumber(cookieCount))
	}
	ctx.RawSetString("session", sessionTable)

	// Auth convenience table (alias for session.auth.data)
	authTable := L.NewTable()
	if sc.SessionData != nil {
		authDataMap := getSessionAuthDataMap(sc.SessionData)
		authTable.RawSetString("data", convertMapToLua(L, authDataMap))
	} else {
		authTable.RawSetString("data", L.NewTable())
	}
	ctx.RawSetString("auth", authTable)

	// Config
	ctx.RawSetString("config", convertMapToLua(L, sc.Config))

	// Request data (from on_request callback)
	ctx.RawSetString("request_data", convertMapToLua(L, sc.RequestData))

	// User-defined variables
	ctx.RawSetString("variables", convertMapToLua(L, sc.Variables))

	// Environment variables
	ctx.RawSetString("env", convertMapToLua(L, sc.Env))

	// Feature flags
	ctx.RawSetString("features", convertMapToLua(L, sc.FeatureFlags))

	// Server variables
	ctx.RawSetString("server", convertMapToLua(L, sc.ServerVars))

	// Request info
	requestTable := L.NewTable()
	if sc.Request != nil {
		requestTable.RawSetString("method", lua.LString(sc.Request.Method))
		requestTable.RawSetString("path", lua.LString(sc.Request.Path))
		requestTable.RawSetString("host", lua.LString(sc.Request.Host))

		// Headers
		headersTable := L.NewTable()
		for k, v := range sc.Request.Headers {
			headersTable.RawSetString(k, lua.LString(v))
		}
		requestTable.RawSetString("headers", headersTable)

		// Query parameters
		queryTable := L.NewTable()
		for k, v := range sc.Request.Query {
			queryTable.RawSetString(k, lua.LString(v))
		}
		requestTable.RawSetString("query", queryTable)
	}
	ctx.RawSetString("request", requestTable)

	// Response phase fields (nil if not in response phase)
	if sc.ResponseStatus != nil {
		ctx.RawSetString("response_status", lua.LNumber(*sc.ResponseStatus))
	}
	if sc.ResponseHeaders != nil {
		respHeadersTable := L.NewTable()
		for k, v := range sc.ResponseHeaders {
			respHeadersTable.RawSetString(k, lua.LString(v))
		}
		ctx.RawSetString("response_headers", respHeadersTable)
	}

	return ctx
}

// Helper functions for reflection-based field access

func getSessionField(sd interface{}, fieldName string) string {
	v := reflect.ValueOf(sd)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return ""
	}
	f := v.FieldByName(fieldName)
	if f.IsValid() && f.Kind() == reflect.String {
		return f.String()
	}
	return ""
}

func getSessionIntField(sd interface{}, fieldName string) int {
	v := reflect.ValueOf(sd)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return 0
	}
	f := v.FieldByName(fieldName)
	if f.IsValid() && f.Kind() == reflect.Int {
		return int(f.Int())
	}
	return 0
}

func isSessionFieldZero(sd interface{}, fieldName string) bool {
	v := reflect.ValueOf(sd)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return true
	}
	f := v.FieldByName(fieldName)
	return !f.IsValid() || f.IsZero()
}

func getSessionAuthField(sd interface{}, fieldName string) string {
	v := reflect.ValueOf(sd)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return ""
	}

	authField := v.FieldByName("AuthData")
	if !authField.IsValid() || authField.IsZero() {
		return ""
	}

	if authField.Kind() == reflect.Ptr {
		authField = authField.Elem()
	}

	f := authField.FieldByName(fieldName)
	if f.IsValid() && f.Kind() == reflect.String {
		return f.String()
	}
	return ""
}

func getSessionAuthDataMap(sd interface{}) map[string]any {
	v := reflect.ValueOf(sd)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return make(map[string]any)
	}

	authField := v.FieldByName("AuthData")
	if !authField.IsValid() || authField.IsZero() {
		return make(map[string]any)
	}

	if authField.Kind() == reflect.Ptr {
		authField = authField.Elem()
	}

	dataField := authField.FieldByName("Data")
	if !dataField.IsValid() || dataField.IsZero() {
		return make(map[string]any)
	}

	if dataMap, ok := dataField.Interface().(map[string]any); ok {
		return dataMap
	}
	return make(map[string]any)
}

func getSessionDataMap(sd interface{}) map[string]any {
	v := reflect.ValueOf(sd)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return make(map[string]any)
	}

	dataField := v.FieldByName("Data")
	if !dataField.IsValid() || dataField.IsZero() {
		return make(map[string]any)
	}

	if dataMap, ok := dataField.Interface().(map[string]any); ok {
		return dataMap
	}
	return make(map[string]any)
}

func getSessionVisited(sd interface{}) []string {
	v := reflect.ValueOf(sd)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return []string{}
	}

	visitedField := v.FieldByName("Visited")
	if !visitedField.IsValid() || visitedField.IsZero() {
		return []string{}
	}

	if visited, ok := visitedField.Interface().([]string); ok {
		return visited
	}
	return []string{}
}

// convertMapToLua converts a Go map to Lua table
func convertMapToLua(L *lua.LState, m map[string]any) *lua.LTable {
	table := L.NewTable()
	if m == nil {
		return table
	}

	for k, v := range m {
		table.RawSetString(k, convertValueToLua(L, v))
	}

	return table
}

// convertSliceToLua converts a Go slice to Lua table
func convertSliceToLua(L *lua.LState, s []string) *lua.LTable {
	table := L.NewTable()
	for _, item := range s {
		table.Append(lua.LString(item))
	}
	return table
}

// convertValueToLua converts a Go value to Lua
func convertValueToLua(L *lua.LState, v interface{}) lua.LValue {
	if v == nil {
		return lua.LNil
	}

	switch val := v.(type) {
	case string:
		return lua.LString(val)
	case int:
		return lua.LNumber(val)
	case int64:
		return lua.LNumber(val)
	case float64:
		return lua.LNumber(val)
	case bool:
		return lua.LBool(val)
	case map[string]any:
		return convertMapToLua(L, val)
	case []interface{}:
		table := L.NewTable()
		for _, item := range val {
			table.Append(convertValueToLua(L, item))
		}
		return table
	case []string:
		table := L.NewTable()
		for _, item := range val {
			table.Append(lua.LString(item))
		}
		return table
	default:
		// Fallback: convert to string
		return lua.LString(reflect.ValueOf(v).String())
	}
}

// NewScriptContextFromRequest creates a ScriptContext from an HTTP request
// This is a convenience helper; in practice, the caller populates ScriptContext directly
// from RequestContext and other sources
func NewScriptContextFromRequest(req *http.Request) *ScriptContext {
	if req == nil {
		return &ScriptContext{
			Config:       make(map[string]any),
			RequestData:  make(map[string]any),
			Variables:    make(map[string]any),
			Secrets:      make(map[string]string),
			Env:          make(map[string]any),
			FeatureFlags: make(map[string]any),
			ServerVars:   make(map[string]any),
		}
	}

	requestData := reqctx.GetRequestData(req.Context())
	if requestData == nil {
		return &ScriptContext{
			Config:       make(map[string]any),
			RequestData:  make(map[string]any),
			Variables:    make(map[string]any),
			Secrets:      make(map[string]string),
			Env:          make(map[string]any),
			FeatureFlags: make(map[string]any),
			ServerVars:   make(map[string]any),
		}
	}

	// Extract request info
	reqInfo := &RequestInfo{
		Method:  req.Method,
		Path:    req.URL.Path,
		Host:    req.Host,
		Headers: make(map[string]string),
		Query:   make(map[string]string),
	}

	// Normalize headers
	for k, v := range req.Header {
		if len(v) > 0 {
			reqInfo.Headers[k] = v[0]
		}
	}

	// Extract query params
	for k, v := range req.URL.Query() {
		if len(v) > 0 {
			reqInfo.Query[k] = v[0]
		}
	}

	return &ScriptContext{
		RequestIP:    getClientIP(req),
		Location:     requestData.Location,
		UserAgent:    requestData.UserAgent,
		Fingerprint:  requestData.Fingerprint,
		SessionData:  requestData.SessionData,
		Config:       requestData.Config,
		RequestData:  requestData.Data,
		Variables:    requestData.Variables,
		Secrets:      requestData.Secrets,
		Env:          requestData.Env,
		FeatureFlags: requestData.FeatureFlags,
		Request:      reqInfo,
	}
}

// getClientIP extracts the client IP from the request
func getClientIP(req *http.Request) string {
	// This is imported from request_context.go in lua package
	// For now, use a simple implementation
	if req == nil {
		return ""
	}

	// Check X-Real-IP header
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Check X-Forwarded-For header
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}

	// Use RemoteAddr
	return req.RemoteAddr
}
