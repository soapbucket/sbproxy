package wasm

import (
	"context"
	"log/slog"
	"strings"
	"sync"
)

// PluginAction represents the action a plugin returns after execution.
type PluginAction int

const (
	// ActionContinue tells the proxy to continue processing the request.
	ActionContinue PluginAction = 0
	// ActionBlock tells the proxy to block/deny the request.
	ActionBlock PluginAction = 1
	// ActionEndStream tells the proxy to stop processing and send the current response.
	ActionEndStream PluginAction = 2
)

// RequestContext holds request/response data accessible to WASM plugins via host functions.
type RequestContext struct {
	// Existing fields
	RequestHeaders  map[string]string
	RequestBody     []byte
	ResponseHeaders map[string]string
	ResponseBody    []byte
	PluginConfig    []byte

	// Request metadata
	RequestMethod  string
	RequestPath    string
	QueryParams    map[string]string
	ResponseStatus int

	// Context data
	Variables  map[string]string // RequestData variables
	ClientIP   string
	GeoCountry string
	SessionID  string

	// Shared data (cross-request state within a plugin)
	SharedData map[string][]byte

	// New context model fields (populated from RequestData bridge fields)
	OriginID      string            // origin.id
	OriginParams  map[string]string // origin.params (stringified)
	OriginSecrets map[string]string // top-level secrets exposed to the current plugin
	ServerVars    map[string]string // server.* (flat)
	Vars          map[string]string // vars.* (stringified)
	Features      map[string]string // features.* (stringified)
	SessionData   map[string]string // session.data (stringified)

	// Extended context fields (auth, client identity, origin metadata, ctx)
	AuthInfo          map[string]string // merged: type + is_authenticated + all auth data fields
	AuthJSON          []byte            // pre-serialized JSON of full auth object
	ClientLocation    map[string]string // geo location fields (country, asn, etc.)
	ClientUserAgent   map[string]string // parsed user agent fields (family, os, device)
	ClientFingerprint map[string]string // fingerprint fields (hash, composite, etc.)
	OriginMeta        map[string]string // origin metadata (hostname, workspace_id, etc.)
	CtxScalars        map[string]string // ctx scalar fields (id, cache_status, debug, no_cache)
	CtxData           map[string]string // ctx mutable plugin state (read/write)

	// Send response (set by plugin to short-circuit)
	SendResponse        bool
	SendResponseCode    int
	SendResponseHeaders map[string]string
	SendResponseBody    []byte

	mu sync.RWMutex
}

// NewRequestContext creates a new RequestContext with initialized maps.
func NewRequestContext() *RequestContext {
	return &RequestContext{
		RequestHeaders:      make(map[string]string),
		ResponseHeaders:     make(map[string]string),
		QueryParams:         make(map[string]string),
		Variables:           make(map[string]string),
		SharedData:          make(map[string][]byte),
		SendResponseHeaders: make(map[string]string),
	}
}

// SetRequestHeader sets a request header value.
func (rc *RequestContext) SetRequestHeader(name, value string) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.RequestHeaders[name] = value
}

// GetRequestHeader returns a request header value.
func (rc *RequestContext) GetRequestHeader(name string) (string, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	v, ok := rc.RequestHeaders[name]
	return v, ok
}

// SetResponseHeader sets a response header value.
func (rc *RequestContext) SetResponseHeader(name, value string) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.ResponseHeaders[name] = value
}

// GetResponseHeader returns a response header value.
func (rc *RequestContext) GetResponseHeader(name string) (string, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	v, ok := rc.ResponseHeaders[name]
	return v, ok
}

// SetRequestBody replaces the request body.
func (rc *RequestContext) SetRequestBody(body []byte) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.RequestBody = body
}

// GetRequestBody returns the request body.
func (rc *RequestContext) GetRequestBody() []byte {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.RequestBody
}

// SetResponseBody replaces the response body.
func (rc *RequestContext) SetResponseBody(body []byte) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.ResponseBody = body
}

// GetResponseBody returns the response body.
func (rc *RequestContext) GetResponseBody() []byte {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.ResponseBody
}

// RemoveRequestHeader removes a request header.
func (rc *RequestContext) RemoveRequestHeader(name string) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	delete(rc.RequestHeaders, name)
}

// RemoveResponseHeader removes a response header.
func (rc *RequestContext) RemoveResponseHeader(name string) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	delete(rc.ResponseHeaders, name)
}

// GetRequestMethod returns the request method.
func (rc *RequestContext) GetRequestMethod() string {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.RequestMethod
}

// GetRequestPath returns the request path.
func (rc *RequestContext) GetRequestPath() string {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.RequestPath
}

// SetRequestPath sets the request path.
func (rc *RequestContext) SetRequestPath(path string) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.RequestPath = path
}

// SetRequestMethod sets the request method.
func (rc *RequestContext) SetRequestMethod(method string) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.RequestMethod = method
}

// GetQueryParam returns a query parameter value.
func (rc *RequestContext) GetQueryParam(name string) (string, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	v, ok := rc.QueryParams[name]
	return v, ok
}

// GetResponseStatus returns the response status code.
func (rc *RequestContext) GetResponseStatus() int {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.ResponseStatus
}

// SetResponseStatus sets the response status code.
func (rc *RequestContext) SetResponseStatus(code int) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.ResponseStatus = code
}

// GetVariable returns a variable value.
func (rc *RequestContext) GetVariable(name string) (string, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	v, ok := rc.Variables[name]
	return v, ok
}

// GetClientIP returns the client IP address.
func (rc *RequestContext) GetClientIP() string {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.ClientIP
}

// GetGeoCountry returns the client's geo country code.
func (rc *RequestContext) GetGeoCountry() string {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.GeoCountry
}

// GetSessionID returns the session ID.
func (rc *RequestContext) GetSessionID() string {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.SessionID
}

// GetOriginSecret returns an allowed origin secret value.
func (rc *RequestContext) GetOriginSecret(name string) (string, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	v, ok := rc.OriginSecrets[name]
	return v, ok
}

// GetSharedData returns shared data by key.
func (rc *RequestContext) GetSharedData(key string) ([]byte, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	v, ok := rc.SharedData[key]
	return v, ok
}

// SetSharedData sets shared data by key.
func (rc *RequestContext) SetSharedData(key string, value []byte) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.SharedData[key] = value
}

// GetAuthInfo returns an auth info field by key.
func (rc *RequestContext) GetAuthInfo(name string) (string, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	v, ok := rc.AuthInfo[name]
	return v, ok
}

// GetAuthJSON returns the pre-serialized JSON of the full auth object.
func (rc *RequestContext) GetAuthJSON() []byte {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.AuthJSON
}

// GetClientLocation returns a client location field by key.
func (rc *RequestContext) GetClientLocation(name string) (string, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	v, ok := rc.ClientLocation[name]
	return v, ok
}

// GetClientUserAgent returns a parsed user agent field by key.
func (rc *RequestContext) GetClientUserAgent(name string) (string, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	v, ok := rc.ClientUserAgent[name]
	return v, ok
}

// GetClientFingerprint returns a client fingerprint field by key.
func (rc *RequestContext) GetClientFingerprint(name string) (string, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	v, ok := rc.ClientFingerprint[name]
	return v, ok
}

// GetOriginMeta returns an origin metadata field by key.
func (rc *RequestContext) GetOriginMeta(name string) (string, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	v, ok := rc.OriginMeta[name]
	return v, ok
}

// GetCtxScalar returns a ctx scalar field by key.
func (rc *RequestContext) GetCtxScalar(name string) (string, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	v, ok := rc.CtxScalars[name]
	return v, ok
}

// GetCtxData returns a mutable ctx data field by key.
func (rc *RequestContext) GetCtxData(name string) (string, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	v, ok := rc.CtxData[name]
	return v, ok
}

// SetCtxData sets a mutable ctx data field.
func (rc *RequestContext) SetCtxData(name, value string) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.CtxData == nil {
		rc.CtxData = make(map[string]string)
	}
	rc.CtxData[name] = value
}

// SetSendResponse configures the plugin to short-circuit with a custom response.
func (rc *RequestContext) SetSendResponse(code int, headers map[string]string, body []byte) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.SendResponse = true
	rc.SendResponseCode = code
	rc.SendResponseHeaders = headers
	rc.SendResponseBody = body
}

// contextKey is an unexported type for context keys in this package.
type contextKey struct{}

// reqCtxKey is the context key for RequestContext.
var reqCtxKey = contextKey{}

// WithRequestContext returns a new context with the given RequestContext.
func WithRequestContext(ctx context.Context, rc *RequestContext) context.Context {
	return context.WithValue(ctx, reqCtxKey, rc)
}

// RequestContextFromContext extracts the RequestContext from a context.
func RequestContextFromContext(ctx context.Context) *RequestContext {
	rc, _ := ctx.Value(reqCtxKey).(*RequestContext)
	return rc
}

// RegisterHostFunctions registers all SoapBucket host functions on the given module builder.
// These functions allow WASM guest modules to interact with request/response data.
func RegisterHostFunctions(builder HostModuleBuilder) HostModuleBuilder {
	return builder.
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetRequestHeader), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{ValueTypeI32, ValueTypeI32}).
		WithParameterNames("name_ptr", "name_len").
		Export("sb_get_request_header").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostSetRequestHeader), []ValueType{ValueTypeI32, ValueTypeI32, ValueTypeI32, ValueTypeI32}, []ValueType{}).
		WithParameterNames("name_ptr", "name_len", "value_ptr", "value_len").
		Export("sb_set_request_header").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetRequestBody), []ValueType{}, []ValueType{ValueTypeI32, ValueTypeI32}).
		Export("sb_get_request_body").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostSetRequestBody), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{}).
		WithParameterNames("ptr", "len").
		Export("sb_set_request_body").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetResponseHeader), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{ValueTypeI32, ValueTypeI32}).
		WithParameterNames("name_ptr", "name_len").
		Export("sb_get_response_header").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostSetResponseHeader), []ValueType{ValueTypeI32, ValueTypeI32, ValueTypeI32, ValueTypeI32}, []ValueType{}).
		WithParameterNames("name_ptr", "name_len", "value_ptr", "value_len").
		Export("sb_set_response_header").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetResponseBody), []ValueType{}, []ValueType{ValueTypeI32, ValueTypeI32}).
		Export("sb_get_response_body").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostSetResponseBody), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{}).
		WithParameterNames("ptr", "len").
		Export("sb_set_response_body").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostLog), []ValueType{ValueTypeI32, ValueTypeI32, ValueTypeI32}, []ValueType{}).
		WithParameterNames("level", "msg_ptr", "msg_len").
		Export("sb_log").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetConfig), []ValueType{}, []ValueType{ValueTypeI32, ValueTypeI32}).
		Export("sb_get_config").
		// Request metadata
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostRemoveRequestHeader), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{}).
		WithParameterNames("name_ptr", "name_len").
		Export("sb_remove_request_header").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetRequestPath), []ValueType{}, []ValueType{ValueTypeI32, ValueTypeI32}).
		Export("sb_get_request_path").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostSetRequestPath), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{}).
		WithParameterNames("path_ptr", "path_len").
		Export("sb_set_request_path").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetRequestMethod), []ValueType{}, []ValueType{ValueTypeI32, ValueTypeI32}).
		Export("sb_get_request_method").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetQueryParam), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{ValueTypeI32, ValueTypeI32}).
		WithParameterNames("name_ptr", "name_len").
		Export("sb_get_query_param").
		// Response metadata
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostRemoveResponseHeader), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{}).
		WithParameterNames("name_ptr", "name_len").
		Export("sb_remove_response_header").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetResponseStatus), []ValueType{}, []ValueType{ValueTypeI32}).
		Export("sb_get_response_status").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostSetResponseStatus), []ValueType{ValueTypeI32}, []ValueType{}).
		WithParameterNames("code").
		Export("sb_set_response_status").
		// Context data
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetVariable), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{ValueTypeI32, ValueTypeI32}).
		WithParameterNames("name_ptr", "name_len").
		Export("sb_get_variable").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetClientIP), []ValueType{}, []ValueType{ValueTypeI32, ValueTypeI32}).
		Export("sb_get_client_ip").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetGeoCountry), []ValueType{}, []ValueType{ValueTypeI32, ValueTypeI32}).
		Export("sb_get_geo_country").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetSessionID), []ValueType{}, []ValueType{ValueTypeI32, ValueTypeI32}).
		Export("sb_get_session_id").
		// Utility functions
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostSendResponse), []ValueType{ValueTypeI32, ValueTypeI32, ValueTypeI32, ValueTypeI32, ValueTypeI32}, []ValueType{}).
		WithParameterNames("status", "headers_ptr", "headers_len", "body_ptr", "body_len").
		Export("sb_send_response").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetSharedData), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{ValueTypeI32, ValueTypeI32}).
		WithParameterNames("key_ptr", "key_len").
		Export("sb_get_shared_data").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostSetSharedData), []ValueType{ValueTypeI32, ValueTypeI32, ValueTypeI32, ValueTypeI32}, []ValueType{}).
		WithParameterNames("key_ptr", "key_len", "val_ptr", "val_len").
		Export("sb_set_shared_data").
		// New context model functions
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetOrigin), []ValueType{}, []ValueType{ValueTypeI32, ValueTypeI32}).
		Export("sb_get_origin").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetOriginParam), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{ValueTypeI32, ValueTypeI32}).
		WithParameterNames("name_ptr", "name_len").
		Export("sb_get_origin_param").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetSecret), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{ValueTypeI32, ValueTypeI32}).
		WithParameterNames("name_ptr", "name_len").
		Export("sb_get_secret").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetServer), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{ValueTypeI32, ValueTypeI32}).
		WithParameterNames("name_ptr", "name_len").
		Export("sb_get_server").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetVar), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{ValueTypeI32, ValueTypeI32}).
		WithParameterNames("name_ptr", "name_len").
		Export("sb_get_var").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetFeature), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{ValueTypeI32, ValueTypeI32}).
		WithParameterNames("name_ptr", "name_len").
		Export("sb_get_feature").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetSession), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{ValueTypeI32, ValueTypeI32}).
		WithParameterNames("name_ptr", "name_len").
		Export("sb_get_session").
		// Extended context: auth, client identity, origin metadata, ctx
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetAuth), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{ValueTypeI32, ValueTypeI32}).
		WithParameterNames("name_ptr", "name_len").
		Export("sb_get_auth").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetAuthJSON), []ValueType{}, []ValueType{ValueTypeI32, ValueTypeI32}).
		Export("sb_get_auth_json").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetClientLocation), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{ValueTypeI32, ValueTypeI32}).
		WithParameterNames("name_ptr", "name_len").
		Export("sb_get_client_location").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetClientUserAgent), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{ValueTypeI32, ValueTypeI32}).
		WithParameterNames("name_ptr", "name_len").
		Export("sb_get_client_user_agent").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetClientFingerprint), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{ValueTypeI32, ValueTypeI32}).
		WithParameterNames("name_ptr", "name_len").
		Export("sb_get_client_fingerprint").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetOriginMeta), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{ValueTypeI32, ValueTypeI32}).
		WithParameterNames("name_ptr", "name_len").
		Export("sb_get_origin_meta").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetCtx), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{ValueTypeI32, ValueTypeI32}).
		WithParameterNames("name_ptr", "name_len").
		Export("sb_get_ctx").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetCtxData), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{ValueTypeI32, ValueTypeI32}).
		WithParameterNames("name_ptr", "name_len").
		Export("sb_get_ctx_data").
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostSetCtxData), []ValueType{ValueTypeI32, ValueTypeI32, ValueTypeI32, ValueTypeI32}, []ValueType{}).
		WithParameterNames("name_ptr", "name_len", "val_ptr", "val_len").
		Export("sb_set_ctx_data")
}

// readString reads a string from WASM module memory at the given pointer and length.
// Delegates to the ReadString helper in memory.go.
func readString(mod WasmModule, ptr, length uint32) (string, bool) {
	s := ReadString(mod, ptr, length)
	if length > 0 && s == "" {
		return "", false
	}
	return s, true
}

// writeToGuest writes data to the guest module's memory using its exported malloc function.
// Delegates to the WriteBytes helper in memory.go.
func writeToGuest(ctx context.Context, mod WasmModule, data []byte) (uint32, uint32) {
	return WriteBytes(ctx, mod, data)
}

// hostGetRequestHeader implements sb_get_request_header(namePtr, nameLen) -> (valuePtr, valueLen)
func hostGetRequestHeader(ctx context.Context, mod WasmModule, stack []uint64) {
	namePtr := uint32(stack[0])
	nameLen := uint32(stack[1])

	rc := RequestContextFromContext(ctx)
	if rc == nil {
		stack[0] = 0
		stack[1] = 0
		return
	}

	name, ok := readString(mod, namePtr, nameLen)
	if !ok {
		stack[0] = 0
		stack[1] = 0
		return
	}

	value, found := rc.GetRequestHeader(strings.ToLower(name))
	if !found {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(value))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostSetRequestHeader implements sb_set_request_header(namePtr, nameLen, valuePtr, valueLen)
func hostSetRequestHeader(ctx context.Context, mod WasmModule, stack []uint64) {
	namePtr := uint32(stack[0])
	nameLen := uint32(stack[1])
	valuePtr := uint32(stack[2])
	valueLen := uint32(stack[3])

	rc := RequestContextFromContext(ctx)
	if rc == nil {
		return
	}

	name, ok := readString(mod, namePtr, nameLen)
	if !ok {
		return
	}

	value, ok := readString(mod, valuePtr, valueLen)
	if !ok {
		return
	}

	rc.SetRequestHeader(name, value)
}

// hostGetRequestBody implements sb_get_request_body() -> (ptr, len)
func hostGetRequestBody(ctx context.Context, mod WasmModule, stack []uint64) {
	rc := RequestContextFromContext(ctx)
	if rc == nil {
		stack[0] = 0
		stack[1] = 0
		return
	}

	body := rc.GetRequestBody()
	ptr, length := writeToGuest(ctx, mod, body)
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostSetRequestBody implements sb_set_request_body(ptr, len)
func hostSetRequestBody(ctx context.Context, mod WasmModule, stack []uint64) {
	ptr := uint32(stack[0])
	length := uint32(stack[1])

	rc := RequestContextFromContext(ctx)
	if rc == nil {
		return
	}

	data, ok := mod.Memory().Read(ptr, length)
	if !ok {
		return
	}

	// Make a copy so we don't hold a reference to WASM memory
	body := make([]byte, len(data))
	copy(body, data)
	rc.SetRequestBody(body)
}

// hostGetResponseHeader implements sb_get_response_header(namePtr, nameLen) -> (valuePtr, valueLen)
func hostGetResponseHeader(ctx context.Context, mod WasmModule, stack []uint64) {
	namePtr := uint32(stack[0])
	nameLen := uint32(stack[1])

	rc := RequestContextFromContext(ctx)
	if rc == nil {
		stack[0] = 0
		stack[1] = 0
		return
	}

	name, ok := readString(mod, namePtr, nameLen)
	if !ok {
		stack[0] = 0
		stack[1] = 0
		return
	}

	value, found := rc.GetResponseHeader(name)
	if !found {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(value))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostSetResponseHeader implements sb_set_response_header(namePtr, nameLen, valuePtr, valueLen)
func hostSetResponseHeader(ctx context.Context, mod WasmModule, stack []uint64) {
	namePtr := uint32(stack[0])
	nameLen := uint32(stack[1])
	valuePtr := uint32(stack[2])
	valueLen := uint32(stack[3])

	rc := RequestContextFromContext(ctx)
	if rc == nil {
		return
	}

	name, ok := readString(mod, namePtr, nameLen)
	if !ok {
		return
	}

	value, ok := readString(mod, valuePtr, valueLen)
	if !ok {
		return
	}

	rc.SetResponseHeader(name, value)
}

// hostGetResponseBody implements sb_get_response_body() -> (ptr, len)
func hostGetResponseBody(ctx context.Context, mod WasmModule, stack []uint64) {
	rc := RequestContextFromContext(ctx)
	if rc == nil {
		stack[0] = 0
		stack[1] = 0
		return
	}

	body := rc.GetResponseBody()
	ptr, length := writeToGuest(ctx, mod, body)
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostSetResponseBody implements sb_set_response_body(ptr, len)
func hostSetResponseBody(ctx context.Context, mod WasmModule, stack []uint64) {
	ptr := uint32(stack[0])
	length := uint32(stack[1])

	rc := RequestContextFromContext(ctx)
	if rc == nil {
		return
	}

	data, ok := mod.Memory().Read(ptr, length)
	if !ok {
		return
	}

	body := make([]byte, len(data))
	copy(body, data)
	rc.SetResponseBody(body)
}

// hostLog implements sb_log(level, msgPtr, msgLen)
func hostLog(ctx context.Context, mod WasmModule, stack []uint64) {
	level := int32(stack[0])
	msgPtr := uint32(stack[1])
	msgLen := uint32(stack[2])

	msg, ok := readString(mod, msgPtr, msgLen)
	if !ok {
		return
	}

	switch {
	case level <= 0:
		slog.DebugContext(ctx, "wasm plugin", "msg", msg)
	case level == 1:
		slog.InfoContext(ctx, "wasm plugin", "msg", msg)
	case level == 2:
		slog.WarnContext(ctx, "wasm plugin", "msg", msg)
	default:
		slog.ErrorContext(ctx, "wasm plugin", "msg", msg)
	}
}

// hostGetConfig implements sb_get_config() -> (ptr, len)
func hostGetConfig(ctx context.Context, mod WasmModule, stack []uint64) {
	rc := RequestContextFromContext(ctx)
	if rc == nil || len(rc.PluginConfig) == 0 {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, rc.PluginConfig)
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}
