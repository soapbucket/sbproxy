// Package cel provides Common Expression Language (CEL) evaluation for dynamic request matching and filtering.
package cel

import (
	"github.com/soapbucket/sbproxy/internal/cache/store"
	"net/http"
	"strings"
	"sync"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	rpcpb "google.golang.org/genproto/googleapis/rpc/context/attribute_context"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// RequestContextPool is a pool of RequestContext objects to reduce allocations
var requestContextPool = sync.Pool{
	New: func() interface{} {
		return &RequestContext{}
	},
}

var protoReqPool = sync.Pool{
	New: func() interface{} {
		return &rpcpb.AttributeContext_Request{}
	},
}

var stringMapPool = sync.Pool{
	New: func() interface{} {
		return make(map[string]string)
	},
}

var interfaceMapPool = sync.Pool{
	New: func() interface{} {
		return make(map[string]interface{})
	},
}

// RequestContext represents the context variables available in CEL expressions.
type RequestContext struct {
	req         *rpcpb.AttributeContext_Request
	oauthUser   map[string]string
	cookies     map[string]string
	params      map[string]string
	requestIP   string
	fingerprint map[string]interface{}
	userAgent   map[string]string
	location    map[string]string
	sessionData map[string]interface{}
	contextData map[string]interface{}
	config      map[string]interface{}
	requestData *reqctx.RequestData // Reference for context model bridge fields

	// cachedMaps to avoid re-creating them during ToVars
	cachedVars           map[string]interface{}
	cachedRequestWrapper map[string]interface{}

	// pooledMaps tracks which maps were taken from pools and should be returned in Release
	pooledFingerprint bool
	pooledUserAgent   bool
	pooledLocation    bool
	pooledSession     bool
}

// convertFingerprintToMap converts a Fingerprint struct to a map for CEL
func convertFingerprintToMap(fp *reqctx.Fingerprint, maps ...map[string]interface{}) map[string]interface{} {
	var m map[string]interface{}
	if len(maps) > 0 {
		m = maps[0]
	}
	if m == nil {
		m = make(map[string]interface{})
	} else {
		clear(m)
	}
	if fp == nil {
		return m
	}
	m["hash"] = fp.Hash
	m["composite"] = fp.Composite
	m["ip_hash"] = fp.IPHash
	m["user_agent_hash"] = fp.UserAgentHash
	m["header_pattern"] = fp.HeaderPattern
	m["tls_hash"] = fp.TLSHash
	m["cookie_count"] = fp.CookieCount
	m["conn_duration_ms"] = fp.ConnDuration.Milliseconds()
	m["version"] = fp.Version
	return m
}

// convertUserAgentToMap converts a uaparser.Result to a map for CEL
func convertUserAgentToMap(ua *reqctx.UserAgent, maps ...map[string]string) map[string]string {
	var m map[string]string
	if len(maps) > 0 {
		m = maps[0]
	}
	if m == nil {
		m = make(map[string]string)
	} else {
		clear(m)
	}
	if ua == nil {
		return m
	}

	// User agent fields
	m["family"] = ua.Family
	m["major"] = ua.Major
	m["minor"] = ua.Minor
	m["patch"] = ua.Patch

	// OS fields
	m["os_family"] = ua.OSFamily
	m["os_major"] = ua.OSMajor
	m["os_minor"] = ua.OSMinor
	m["os_patch"] = ua.OSPatch

	// Device fields
	m["device_family"] = ua.DeviceFamily
	m["device_brand"] = ua.DeviceBrand
	m["device_model"] = ua.DeviceModel

	return m
}

// convertLocationToMap converts a Location to a map for CEL
func convertLocationToMap(loc *reqctx.Location, maps ...map[string]string) map[string]string {
	var m map[string]string
	if len(maps) > 0 {
		m = maps[0]
	}
	if m == nil {
		m = make(map[string]string)
	} else {
		clear(m)
	}
	if loc == nil {
		return m
	}
	m["country"] = loc.Country
	m["country_code"] = loc.CountryCode
	m["continent"] = loc.Continent
	m["continent_code"] = loc.ContinentCode
	m["asn"] = loc.ASN
	m["as_name"] = loc.ASName
	m["as_domain"] = loc.ASDomain
	return m
}

// convertSessionDataToMap converts session data to a map for CEL
func convertSessionDataToMap(sd *reqctx.SessionData, maps ...map[string]interface{}) map[string]interface{} {
	var m map[string]interface{}
	if len(maps) > 0 {
		m = maps[0]
	}
	if m == nil {
		m = make(map[string]interface{})
	} else {
		clear(m)
	}
	if sd == nil {
		return m
	}

	m["id"] = sd.ID
	m["expires"] = sd.Expires

	// Extract is_authenticated from AuthData presence
	if sd.AuthData != nil {
		m["is_authenticated"] = true

		// Create auth object with type, data object, and all data fields directly accessible
		authMap := make(map[string]interface{})
		authMap["type"] = sd.AuthData.Type

		// Add data as nested object
		if sd.AuthData.Data != nil {
			authMap["data"] = sd.AuthData.Data

			// Also merge all data fields directly into auth object for convenience
			for k, v := range sd.AuthData.Data {
				authMap[k] = v
			}
		}

		m["auth"] = authMap
	} else {
		m["is_authenticated"] = false
	}

	if len(sd.Visited) > 0 {
		m["visited"] = sd.Visited
	}

	if len(sd.Data) > 0 {
		m["data"] = sd.Data
	}
	return m
}

// NewRequestContext creates a new RequestContext from an HTTP request.
// IMPORTANT: The caller MUST call Release() when finished with the RequestContext.
func NewRequestContext(req *http.Request) *RequestContext {
	rc := requestContextPool.Get().(*RequestContext)

	// Reset all pooling flags for the new request
	rc.pooledFingerprint = false
	rc.pooledUserAgent = false
	rc.pooledLocation = false
	rc.pooledSession = false
	rc.cachedVars = nil
	rc.cachedRequestWrapper = nil

	r := protoReqPool.Get().(*rpcpb.AttributeContext_Request)
	if r.Headers == nil {
		r.Headers = make(map[string]string)
	} else {
		clear(r.Headers)
	}

	r.Path = req.URL.Path
	r.Method = req.Method
	r.Host = req.Host
	r.Protocol = req.Proto
	r.Scheme = req.URL.Scheme
	r.Query = req.URL.RawQuery
	r.Time = timestamppb.Now()
	r.Size = req.ContentLength

	// Store headers under lowercase keys only (single entry per header).
	// Matches HTTP/2 convention where header names are always lowercase.
	// CEL expressions use: request.headers["content-type"], request.headers["x-admin"]
	for k, v := range req.Header {
		headerKey := strings.ToLower(k)

		var val string
		if len(v) == 0 {
			val = ""
		} else if len(v) == 1 {
			val = v[0]
		} else {
			capacity := 0
			for _, s := range v {
				capacity += len(s)
			}
			capacity += len(v) - 1 // commas

			headerBuilder := cacher.GetBuilderWithSize(capacity)
			headerBuilder.WriteString(v[0])
			for i := 1; i < len(v); i++ {
				headerBuilder.WriteByte(',')
				headerBuilder.WriteString(v[i])
			}
			val = headerBuilder.String()
			cacher.PutBuilder(headerBuilder)
		}

		r.Headers[headerKey] = val
	}

	// Extract cookies
	cookies := stringMapPool.Get().(map[string]string)
	clear(cookies)
	for _, cookie := range req.Cookies() {
		cookies[cookie.Name] = cookie.Value
	}

	// Extract query parameters
	params := stringMapPool.Get().(map[string]string)
	clear(params)
	query := req.URL.Query()
	for k, v := range query {
		if len(v) > 0 {
			params[k] = v[0]
		}
	}

	requestData := reqctx.GetRequestData(req.Context())

	// Initialize empty maps if requestData is nil
	var fingerprintMap map[string]interface{}
	var userAgentMap map[string]string
	var locationMap map[string]string
	var sessionDataMap map[string]interface{}
	var contextDataMap map[string]any
	var configMap map[string]any

	if requestData != nil {
		// Convert to CEL-compatible maps using pools
		fingerprintMap = convertFingerprintToMap(requestData.Fingerprint, interfaceMapPool.Get().(map[string]interface{}))
		rc.pooledFingerprint = true

		userAgentMap = convertUserAgentToMap(requestData.UserAgent, stringMapPool.Get().(map[string]string))
		rc.pooledUserAgent = true

		locationMap = convertLocationToMap(requestData.Location, stringMapPool.Get().(map[string]string))
		rc.pooledLocation = true

		sessionDataMap = convertSessionDataToMap(requestData.SessionData, interfaceMapPool.Get().(map[string]interface{}))
		rc.pooledSession = true

		contextDataMap = requestData.Data
		configMap = requestData.Config
	} else {
		// Return empty maps when requestData is nil
		fingerprintMap = interfaceMapPool.Get().(map[string]interface{})
		clear(fingerprintMap)
		rc.pooledFingerprint = true

		userAgentMap = stringMapPool.Get().(map[string]string)
		clear(userAgentMap)
		rc.pooledUserAgent = true

		locationMap = stringMapPool.Get().(map[string]string)
		clear(locationMap)
		rc.pooledLocation = true

		sessionDataMap = interfaceMapPool.Get().(map[string]interface{})
		clear(sessionDataMap)
		rc.pooledSession = true

		contextDataMap = make(map[string]any)
		configMap = make(map[string]any)
	}

	// Extract client IP from request
	clientIP := getClientIP(req.RemoteAddr, r.Headers)

	rc.req = r
	rc.cookies = cookies
	rc.params = params
	rc.requestIP = clientIP
	rc.fingerprint = fingerprintMap
	rc.userAgent = userAgentMap
	rc.location = locationMap
	rc.sessionData = sessionDataMap
	rc.contextData = contextDataMap
	rc.config = configMap
	rc.requestData = requestData

	return rc
}

// Release returns the RequestContext to the pool
func (rc *RequestContext) Release() {
	if rc == nil {
		return
	}

	// Put maps back to their respective pools
	if rc.req != nil {
		protoReqPool.Put(rc.req)
	}
	if rc.cookies != nil {
		clear(rc.cookies)
		stringMapPool.Put(rc.cookies)
	}
	if rc.params != nil {
		clear(rc.params)
		stringMapPool.Put(rc.params)
	}
	if rc.pooledUserAgent && rc.userAgent != nil {
		clear(rc.userAgent)
		stringMapPool.Put(rc.userAgent)
	}
	if rc.pooledLocation && rc.location != nil {
		clear(rc.location)
		stringMapPool.Put(rc.location)
	}
	if rc.pooledFingerprint && rc.fingerprint != nil {
		clear(rc.fingerprint)
		interfaceMapPool.Put(rc.fingerprint)
	}
	if rc.pooledSession && rc.sessionData != nil {
		clear(rc.sessionData)
		interfaceMapPool.Put(rc.sessionData)
	}
	if rc.cachedRequestWrapper != nil {
		clear(rc.cachedRequestWrapper)
		interfaceMapPool.Put(rc.cachedRequestWrapper)
	}
	if rc.cachedVars != nil {
		clear(rc.cachedVars)
		interfaceMapPool.Put(rc.cachedVars)
	}

	// Clear fields to avoid memory leaks and ensure fresh state
	rc.req = nil
	rc.oauthUser = nil
	rc.cookies = nil
	rc.params = nil
	rc.requestIP = ""
	rc.fingerprint = nil
	rc.userAgent = nil
	rc.location = nil
	rc.sessionData = nil
	rc.contextData = nil
	rc.config = nil
	rc.requestData = nil
	rc.cachedVars = nil
	rc.cachedRequestWrapper = nil

	// Reset pooling flags
	rc.pooledFingerprint = false
	rc.pooledUserAgent = false
	rc.pooledLocation = false
	rc.pooledSession = false

	requestContextPool.Put(rc)
}

// GetRequestContext returns the pooled RequestContext from the request context.
// It lazily initializes it if not already present in reqctx.RequestData.
func GetRequestContext(req *http.Request) *RequestContext {
	rd := reqctx.GetRequestData(req.Context())
	if rd != nil && rd.CELContext != nil {
		if rc, ok := rd.CELContext.(*RequestContext); ok {
			return rc
		}
	}

	rc := NewRequestContext(req)
	if rd != nil {
		rd.CELContext = rc
	}
	return rc
}

// Request returns the underlying protobuf request object for direct field access.
func (rc *RequestContext) Request() *rpcpb.AttributeContext_Request {
	return rc.req
}

// createRequestWrapper creates a map wrapper around the protobuf request that includes
// all protobuf fields plus a custom "data" field for RequestData.Data access.
func (rc *RequestContext) createRequestWrapper() map[string]interface{} {
	if rc.cachedRequestWrapper != nil {
		return rc.cachedRequestWrapper
	}

	reqWrapper := interfaceMapPool.Get().(map[string]interface{})
	clear(reqWrapper)

	// Copy all protobuf fields to the wrapper
	reqWrapper["id"] = rc.req.Id
	reqWrapper["method"] = rc.req.Method
	reqWrapper["path"] = rc.req.Path
	reqWrapper["host"] = rc.req.Host
	reqWrapper["scheme"] = rc.req.Scheme
	reqWrapper["query"] = rc.req.Query
	reqWrapper["protocol"] = rc.req.Protocol
	reqWrapper["headers"] = rc.req.Headers
	reqWrapper["size"] = rc.req.Size
	reqWrapper["time"] = rc.req.Time

	// Add request.data field pointing to RequestData.Data
	if rc.contextData != nil {
		reqWrapper["data"] = rc.contextData
	} else {
		reqWrapper["data"] = make(map[string]interface{})
	}

	// Add Snapshot fields to the request namespace (body_json, is_json, body, etc.)
	if rc.requestData != nil && rc.requestData.Snapshot != nil {
		snap := rc.requestData.Snapshot
		reqWrapper["is_json"] = snap.IsJSON
		if snap.BodyJSON != nil {
			reqWrapper["body_json"] = snap.BodyJSON
		}
		if snap.Body != nil {
			reqWrapper["body"] = string(snap.Body)
		}
		if snap.ContentType != "" {
			reqWrapper["content_type"] = snap.ContentType
		}
		if snap.RemoteAddr != "" {
			reqWrapper["remote_addr"] = snap.RemoteAddr
		}
		// Snapshot method overrides live request method (pre-modification snapshot)
		if snap.Method != "" {
			reqWrapper["method"] = snap.Method
		}
	}

	rc.cachedRequestWrapper = reqWrapper
	return reqWrapper
}

// ToVars converts the RequestContext to a map suitable for CEL evaluation.
// Uses the 9-namespace model: origin, server, vars, features, request, session, client, ctx, cache.
func (rc *RequestContext) ToVars() map[string]interface{} {
	if rc.cachedVars != nil {
		return rc.cachedVars
	}

	// Create a wrapper map for request that includes protobuf fields plus data field
	requestWrapper := rc.createRequestWrapper()

	vars := interfaceMapPool.Get().(map[string]interface{})
	clear(vars)

	// 9-namespace model
	vars["request"] = requestWrapper
	vars["session"] = rc.sessionData
	vars["origin"] = rc.buildOriginVars()
	vars["server"] = rc.buildServerVars()
	vars["vars"] = rc.buildVarsNamespace()
	vars["features"] = rc.buildFeaturesVars()
	vars["client"] = rc.buildClientVars()
	vars["ctx"] = rc.buildCtxVars()

	rc.cachedVars = vars
	return vars
}

// buildOriginVars builds the origin namespace from RequestData bridge fields.
func (rc *RequestContext) buildOriginVars() map[string]interface{} {
	m := make(map[string]interface{})
	if rc.requestData == nil || rc.requestData.OriginCtx == nil {
		return m
	}
	o := rc.requestData.OriginCtx
	m["id"] = o.ID
	m["hostname"] = o.Hostname
	m["workspace_id"] = o.WorkspaceID
	m["environment"] = o.Environment
	m["version"] = o.Version
	m["name"] = o.Name
	if o.Params != nil {
		m["params"] = o.Params
	}
	if o.Tags != nil {
		m["tags"] = o.Tags
	}
	return m
}

// buildServerVars builds the server namespace from RequestData bridge fields.
func (rc *RequestContext) buildServerVars() map[string]interface{} {
	m := make(map[string]interface{})
	if rc.requestData == nil || rc.requestData.ServerCtx == nil {
		return m
	}
	s := rc.requestData.ServerCtx
	m["instance_id"] = s.InstanceID
	m["version"] = s.Version
	m["build_hash"] = s.BuildHash
	m["start_time"] = s.StartTime
	m["hostname"] = s.Hostname
	m["environment"] = s.Environment
	if s.Custom != nil {
		m["custom"] = s.Custom
	}
	if s.Env != nil {
		m["env"] = s.Env
	}
	return m
}

// buildVarsNamespace builds the vars namespace from RequestData bridge fields.
func (rc *RequestContext) buildVarsNamespace() map[string]interface{} {
	if rc.requestData == nil || rc.requestData.VarsCtx == nil {
		return make(map[string]interface{})
	}
	return rc.requestData.VarsCtx.Data
}

// buildFeaturesVars builds the features namespace from RequestData bridge fields.
func (rc *RequestContext) buildFeaturesVars() map[string]interface{} {
	if rc.requestData == nil || rc.requestData.FeaturesCtx == nil {
		return make(map[string]interface{})
	}
	return rc.requestData.FeaturesCtx.Data
}

// buildClientVars builds the client namespace from RequestData bridge fields.
// Always populates location, user_agent, and fingerprint sub-keys (as empty maps if nil)
// so CEL expressions can safely use size(client.location) without key errors.
func (rc *RequestContext) buildClientVars() map[string]interface{} {
	m := make(map[string]interface{}, 4)
	if rc.requestData == nil || rc.requestData.ClientCtx == nil {
		m["ip"] = rc.requestIP
		m["location"] = make(map[string]string)
		m["user_agent"] = make(map[string]string)
		m["fingerprint"] = make(map[string]interface{})
		return m
	}
	c := rc.requestData.ClientCtx
	m["ip"] = c.IP
	if c.Location != nil {
		m["location"] = convertLocationToMap(c.Location)
	} else {
		m["location"] = make(map[string]string)
	}
	if c.UserAgent != nil {
		m["user_agent"] = convertUserAgentToMap(c.UserAgent)
	} else {
		m["user_agent"] = make(map[string]string)
	}
	if c.Fingerprint != nil {
		m["fingerprint"] = convertFingerprintToMap(c.Fingerprint)
	} else {
		m["fingerprint"] = make(map[string]interface{})
	}
	return m
}

// buildCtxVars builds the ctx namespace from RequestData bridge fields.
func (rc *RequestContext) buildCtxVars() map[string]interface{} {
	m := make(map[string]interface{})
	if rc.requestData == nil || rc.requestData.CtxObj == nil {
		return m
	}
	c := rc.requestData.CtxObj
	m["id"] = c.ID
	m["cache_status"] = c.CacheStatus
	m["debug"] = c.Debug
	m["no_cache"] = c.NoCache
	if c.Data != nil {
		m["data"] = c.Data
	}
	return m
}
