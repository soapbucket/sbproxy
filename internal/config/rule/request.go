// Package rule implements rule-based request matching using conditions, expressions, and pattern matching.
package rule

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/parser"
	"github.com/graphql-go/graphql/language/source"

	"github.com/soapbucket/sbproxy/internal/extension/cel"
	"github.com/soapbucket/sbproxy/internal/extension/lua"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// EmptyRequestRule is a variable for empty request rule.
var EmptyRequestRule = RequestRule{}

// HeaderConditions groups header matching criteria
type HeaderConditions struct {
	Exact    map[string]string `json:"exact,omitempty"`     // Headers that must match exact values
	Exists   []string          `json:"exists,omitempty"`    // Headers that must exist
	NotExist []string          `json:"not_exist,omitempty"` // Headers that must not exist
}

// QueryConditions groups query parameter matching criteria
type QueryConditions struct {
	Exact    map[string]string `json:"exact,omitempty"`     // Query params that must match exact values
	Exists   []string          `json:"exists,omitempty"`    // Query params that must exist
	NotExist []string          `json:"not_exist,omitempty"` // Query params that must not exist
}

// ParamConditions groups form parameter matching criteria
type ParamConditions struct {
	Exact    map[string]string `json:"exact,omitempty"`     // Params that must match exact values
	Exists   []string          `json:"exists,omitempty"`    // Params that must exist
	NotExist []string          `json:"not_exist,omitempty"` // Params that must not exist
}

// URLConditions groups URL matching criteria
type URLConditions struct {
	Exact    string `json:"exact,omitempty"`    // Full URL must match exactly
	Contains string `json:"contains,omitempty"` // URL must contain this substring (ignored if Exact is set)
}

// PathConditions groups path matching criteria
type PathConditions struct {
	Exact    string `json:"exact,omitempty"`    // Path must match exactly
	Contains string `json:"contains,omitempty"` // Path must contain this substring (ignored if Exact is set)
	Prefix   string `json:"prefix,omitempty"`   // Path must start with this prefix (ignored if Exact is set)
	Suffix   string `json:"suffix,omitempty"`   // Path must end with this suffix (ignored if Exact or Prefix is set)
}

// IPConditions groups IP address matching criteria
type IPConditions struct {
	IPs   []string `json:"ips,omitempty"`    // Individual IP addresses (IPv4 and IPv6) that must match
	CIDRs []string `json:"cidrs,omitempty"`  // CIDR ranges (IPv4 and IPv6) that must match
	NotIn []string `json:"not_in,omitempty"` // IPs or CIDRs that must NOT match
}

// RequestRule represents a request rule.
type RequestRule struct {
	Methods       []string `json:"methods,omitempty"`
	Protocol      string   `json:"protocol,omitempty"`       // Single protocol: "http1", "http2", "http3", "websocket", "grpc", "http2_bidirectional", or "http" (matches http1/http2/http3)
	Protocols     []string `json:"protocols,omitempty"`      // Multiple protocols: array of protocol types (at least one must match)
	ProtoVersion  string   `json:"proto_version,omitempty"`  // Single protocol version: "1.0", "1.1", "2.0", "3.0"
	ProtoVersions []string `json:"proto_versions,omitempty"` // Multiple protocol versions: array of version strings (at least one must match)

	URL    *URLConditions  `json:"url,omitempty"`
	Path   *PathConditions `json:"path,omitempty"`
	Scheme string          `json:"scheme,omitempty"`

	Headers *HeaderConditions `json:"headers,omitempty"`
	Query   *QueryConditions  `json:"query,omitempty"`
	Params  *ParamConditions  `json:"params,omitempty"`

	ContentTypes []string `json:"content_types,omitempty"`

	IP *IPConditions `json:"ip,omitempty"`

	// MaxMind location matching
	Location *LocationConditions `json:"location,omitempty"`

	// UAParser matching
	UserAgent *UserAgentConditions `json:"user_agent,omitempty"`

	// User matching
	AuthConditions *AuthConditions `json:"auth_conditions,omitempty"`

	// GraphQL query matching
	GraphQL *GraphQLConditions `json:"graphql,omitempty"`

	// JSON body matching
	JSON *JSONConditions `json:"json,omitempty"`

	CELExpr   string `json:"cel_expr,omitempty"`
	LuaScript string `json:"lua_script,omitempty"`

	celexpr   cel.Matcher `json:"-"`
	luascript lua.Matcher `json:"-"`
}

// UnmarshalJSON implements the json.Unmarshaler interface for RequestRule.
func (r *RequestRule) UnmarshalJSON(data []byte) error {
	type Alias RequestRule
	alias := (*Alias)(r)
	if err := json.Unmarshal(data, alias); err != nil {
		return err
	}

	if r.CELExpr != "" {
		celexpr, err := cel.NewMatcher(r.CELExpr)
		if err != nil {
			return err
		}
		r.celexpr = celexpr
	}
	if r.LuaScript != "" {
		luascript, err := lua.NewMatcher(r.LuaScript)
		if err != nil {
			return err
		}
		r.luascript = luascript
	}

	return nil
}

// AuthConditions is a slice type for auth conditions.
type AuthConditions []AuthCondition

// AuthCondition represents a auth condition.
type AuthCondition struct {
	Type string `json:"auth_type"`

	AuthConditionRules []AuthConditionRule `json:"auth_condition_rules,omitempty"`
}

// AuthConditionRule matches auth data using JSON path notation
// Supports various matching modes: exact, contains, startsWith, endsWith, regex
type AuthConditionRule struct {
	Path string `json:"path"` // JSON path like "user.email", "roles.0", "data.department"

	// Matching options (use one)
	Value      string   `json:"value,omitempty"`       // Exact match
	Values     []string `json:"values,omitempty"`      // Match any of these values (OR logic)
	Contains   string   `json:"contains,omitempty"`    // Value contains this string
	StartsWith string   `json:"starts_with,omitempty"` // Value starts with this string
	EndsWith   string   `json:"ends_with,omitempty"`   // Value ends with this string
	Regex      string   `json:"regex,omitempty"`       // Regex pattern match

	CELExpr string      `json:"cel_expr,omitempty"`
	celExpr cel.Matcher `json:"-"`

	LuaScript string      `json:"lua_script,omitempty"`
	luaScript lua.Matcher `json:"-"`
}

// UnmarshalJSON implements the json.Unmarshaler interface for AuthConditionRule.
func (r *AuthConditionRule) UnmarshalJSON(data []byte) error {
	type Alias AuthConditionRule
	alias := (*Alias)(r)
	if err := json.Unmarshal(data, alias); err != nil {
		return err
	}

	// Initialize CEL matcher for advanced auth data matching
	if r.CELExpr != "" {
		celExpr, err := cel.NewMatcher(r.CELExpr)
		if err != nil {
			return err
		}
		r.celExpr = celExpr
	}

	// Initialize Lua matcher for advanced auth data matching
	if r.LuaScript != "" {
		luaScript, err := lua.NewMatcher(r.LuaScript)
		if err != nil {
			return err
		}
		r.luaScript = luaScript
	}

	return nil
}

// MaxMindRule defines matching criteria for MaxMind location data
type LocationConditions struct {
	CountryCodes   []string `json:"country_codes,omitempty"`   // ISO country codes (e.g., "US", "GB")
	Countries      []string `json:"countries,omitempty"`       // Country names
	ContinentCodes []string `json:"continent_codes,omitempty"` // Continent codes (e.g., "NA", "EU")
	Continents     []string `json:"continents,omitempty"`      // Continent names
	ASNs           []string `json:"asns,omitempty"`            // ASN numbers
	ASNames        []string `json:"as_names,omitempty"`        // AS names
	ASDomains      []string `json:"as_domains,omitempty"`      // AS domains
}

// UAParserRule defines matching criteria for UAParser results
type UserAgentConditions struct {
	// User Agent (browser) matching
	UserAgentFamilies []string `json:"user_agent_families,omitempty"` // Browser families (e.g., "Chrome", "Firefox")
	UserAgentMajors   []string `json:"user_agent_majors,omitempty"`   // Major versions
	UserAgentMinors   []string `json:"user_agent_minors,omitempty"`   // Minor versions

	// OS matching
	OSFamilies []string `json:"os_families,omitempty"` // OS families (e.g., "Windows", "Mac OS X")
	OSMajors   []string `json:"os_majors,omitempty"`   // OS major versions
	OSMinors   []string `json:"os_minors,omitempty"`   // OS minor versions

	// Device matching
	DeviceFamilies []string `json:"device_families,omitempty"` // Device families (e.g., "iPhone", "iPad")
	DeviceBrands   []string `json:"device_brands,omitempty"`   // Device brands
	DeviceModels   []string `json:"device_models,omitempty"`   // Device models
}

// GraphQLConditions groups GraphQL query matching criteria
type GraphQLConditions struct {
	// Operation name matching
	OperationName      string   `json:"operation_name,omitempty"`       // Exact operation name match
	OperationNames     []string `json:"operation_names,omitempty"`      // Match any of these operation names
	OperationNameRegex string   `json:"operation_name_regex,omitempty"` // Regex pattern for operation name

	// Operation type matching (query, mutation, subscription)
	OperationTypes []string `json:"operation_types,omitempty"` // Match any of these operation types

	// Field name matching
	Fields      []string `json:"fields,omitempty"`       // Match if query contains any of these field names
	FieldsAll   []string `json:"fields_all,omitempty"`   // Match if query contains all of these field names
	FieldsRegex string   `json:"fields_regex,omitempty"` // Regex pattern to match field names

	// Query string matching
	QueryContains string `json:"query_contains,omitempty"` // Query string must contain this substring
}

// JSONConditions groups JSON body matching criteria
type JSONConditions struct {
	// Field path matching (JSONPath-like notation)
	Fields      []string `json:"fields,omitempty"`       // Match if JSON contains any of these field paths (e.g., "user.id", "data.items")
	FieldsAll   []string `json:"fields_all,omitempty"`   // Match if JSON contains all of these field paths
	FieldsRegex string   `json:"fields_regex,omitempty"` // Regex pattern to match field paths

	// Value matching
	FieldValue      map[string]string   `json:"field_value,omitempty"`       // Match exact field values (e.g., {"user.role": "admin"})
	FieldValueIn    map[string][]string `json:"field_value_in,omitempty"`    // Match if field value is in list
	FieldValueRegex map[string]string   `json:"field_value_regex,omitempty"` // Match field values with regex

	// Body string matching
	BodyContains string `json:"body_contains,omitempty"` // JSON body must contain this substring
}

// IsEmpty reports whether the RequestRule is empty.
func (r RequestRule) IsEmpty() bool {
	if len(r.Methods) > 0 {
		return false
	}
	if r.Protocol != "" {
		return false
	}
	if len(r.Protocols) > 0 {
		return false
	}
	if r.ProtoVersion != "" {
		return false
	}
	if len(r.ProtoVersions) > 0 {
		return false
	}
	if r.URL != nil && (r.URL.Exact != "" || r.URL.Contains != "") {
		return false
	}
	if r.Path != nil && (r.Path.Exact != "" || r.Path.Contains != "" || r.Path.Prefix != "" || r.Path.Suffix != "") {
		return false
	}
	if r.Scheme != "" {
		return false
	}
	if r.Headers != nil && (len(r.Headers.Exact) > 0 || len(r.Headers.Exists) > 0 || len(r.Headers.NotExist) > 0) {
		return false
	}
	if r.Query != nil && (len(r.Query.Exact) > 0 || len(r.Query.Exists) > 0 || len(r.Query.NotExist) > 0) {
		return false
	}
	if r.Params != nil && (len(r.Params.Exact) > 0 || len(r.Params.Exists) > 0 || len(r.Params.NotExist) > 0) {
		return false
	}
	if len(r.ContentTypes) > 0 {
		return false
	}
	if r.IP != nil && (len(r.IP.IPs) > 0 || len(r.IP.CIDRs) > 0 || len(r.IP.NotIn) > 0) {
		return false
	}
	if r.Location != nil {
		return false
	}
	if r.UserAgent != nil {
		return false
	}

	if r.AuthConditions != nil {
		return false
	}

	if r.GraphQL != nil {
		return false
	}

	if r.JSON != nil {
		return false
	}

	if r.CELExpr != "" {
		return false
	}
	if r.LuaScript != "" {
		return false
	}
	return true
}

// RequestRules is a slice type for request rules.
type RequestRules []RequestRule

// optimizationContext caches values that are expensive to compute or allocate
// during a single Match cycle across multiple rules.
type optimizationContext struct {
	protocol       string
	protoVersion   string
	query          url.Values
	queryParsed    bool
	clientIP       string
	clientIPParsed bool
	urlStr         string
}

// Match performs the match operation on the RequestRules.
func (r RequestRules) Match(req *http.Request) bool {
	if len(r) == 0 {
		return true
	}

	// Optimization: Use a context to cache expensive operations across rules
	ctx := optimizationContext{}

	for _, rule := range r {
		if rule.IsEmpty() {
			return true
		}

		if rule.matchWithContext(req, &ctx) {
			return true
		}
	}
	return false
}

// Match performs the match operation on the RequestRule.
func (r *RequestRule) Match(req *http.Request) bool {
	return r.matchWithContext(req, &optimizationContext{})
}

func (r *RequestRule) matchWithContext(req *http.Request, ctx *optimizationContext) bool {
	// Match protocol
	if r.Protocol != "" || len(r.Protocols) > 0 {
		if ctx.protocol == "" {
			ctx.protocol = detectProtocol(req)
		}

		// Check single protocol match
		if r.Protocol != "" {
			protocolLower := strings.ToLower(r.Protocol)
			if !matchProtocol(protocolLower, ctx.protocol) {
				return false
			}
		}

		// Check multiple protocols match
		if len(r.Protocols) > 0 {
			matched := false
			for _, protocol := range r.Protocols {
				if matchProtocol(strings.ToLower(protocol), ctx.protocol) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}

	// Match protocol version
	if r.ProtoVersion != "" || len(r.ProtoVersions) > 0 {
		if ctx.protoVersion == "" {
			ctx.protoVersion = getProtoVersion(req)
		}

		// Check single version match
		if r.ProtoVersion != "" {
			if r.ProtoVersion != ctx.protoVersion {
				return false
			}
		}

		// Check multiple versions match
		if len(r.ProtoVersions) > 0 {
			matched := false
			for _, version := range r.ProtoVersions {
				if version == ctx.protoVersion {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}

	// Match methods (case-insensitive, at least one must match)
	if len(r.Methods) > 0 {
		methodMatched := false
		for _, method := range r.Methods {
			if strings.EqualFold(method, req.Method) {
				methodMatched = true
				break
			}
		}
		if !methodMatched {
			return false
		}
	}

	// Match URL
	if r.URL != nil && (r.URL.Exact != "" || r.URL.Contains != "") {
		if ctx.urlStr == "" {
			ctx.urlStr = req.URL.String()
		}
		if r.URL.Exact != "" {
			if r.URL.Exact != ctx.urlStr {
				return false
			}
		} else if r.URL.Contains != "" {
			if !strings.Contains(ctx.urlStr, r.URL.Contains) {
				return false
			}
		}
	}

	// Match scheme
	if r.Scheme != "" && (r.URL == nil || r.URL.Exact == "") {
		if req.URL.Scheme == "" {
			if r.Scheme != "http" {
				return false
			}
		} else if r.Scheme != req.URL.Scheme {
			return false
		}
	}

	// Match path
	if r.Path != nil && (r.URL == nil || r.URL.Exact == "") {
		if r.Path.Exact != "" {
			if r.Path.Exact != req.URL.Path {
				return false
			}
		} else if r.Path.Prefix != "" {
			if !strings.HasPrefix(req.URL.Path, r.Path.Prefix) {
				return false
			}
		} else if r.Path.Suffix != "" {
			if !strings.HasSuffix(req.URL.Path, r.Path.Suffix) {
				return false
			}
		} else if r.Path.Contains != "" {
			if !strings.Contains(req.URL.Path, r.Path.Contains) {
				return false
			}
		}
	}

	// Match query parameters
	if r.Query != nil {
		if !ctx.queryParsed {
			ctx.query = req.URL.Query()
			ctx.queryParsed = true
		}
		// Match exact values
		if len(r.Query.Exact) > 0 {
			for key, value := range r.Query.Exact {
				if ctx.query.Get(key) != value {
					return false
				}
			}
		}
		// Match exists
		if len(r.Query.Exists) > 0 {
			for _, key := range r.Query.Exists {
				if ctx.query.Get(key) == "" {
					return false
				}
			}
		}
		// Match not exist
		if len(r.Query.NotExist) > 0 {
			for _, key := range r.Query.NotExist {
				if ctx.query.Get(key) != "" {
					return false
				}
			}
		}
	}

	// Match params (form parameters)
	if r.Params != nil && (len(r.Params.Exact) > 0 || len(r.Params.Exists) > 0 || len(r.Params.NotExist) > 0) {
		if err := req.ParseForm(); err == nil {
			// Match exact values
			if len(r.Params.Exact) > 0 {
				for key, value := range r.Params.Exact {
					if req.Form.Get(key) != value {
						return false
					}
				}
			}
			// Match exists
			if len(r.Params.Exists) > 0 {
				for _, key := range r.Params.Exists {
					if req.Form.Get(key) == "" {
						return false
					}
				}
			}
			// Match not exist
			if len(r.Params.NotExist) > 0 {
				for _, key := range r.Params.NotExist {
					if req.Form.Get(key) != "" {
						return false
					}
				}
			}
		} else {
			if len(r.Params.Exact) > 0 || len(r.Params.Exists) > 0 {
				return false
			}
		}
	}

	// Match headers
	if r.Headers != nil {
		if len(r.Headers.Exact) > 0 {
			for key, value := range r.Headers.Exact {
				if req.Header.Get(key) != value {
					return false
				}
			}
		}
		if len(r.Headers.Exists) > 0 {
			for _, key := range r.Headers.Exists {
				if req.Header.Get(key) == "" {
					return false
				}
			}
		}
		if len(r.Headers.NotExist) > 0 {
			for _, key := range r.Headers.NotExist {
				if req.Header.Get(key) != "" {
					return false
				}
			}
		}
	}

	// Match content types
	if len(r.ContentTypes) > 0 {
		contentType := req.Header.Get("Content-Type")
		if contentType != "" {
			semicolonIdx := strings.IndexByte(contentType, ';')
			var baseContentType string
			if semicolonIdx >= 0 {
				baseContentType = contentType[:semicolonIdx]
			} else {
				baseContentType = contentType
			}
			baseContentTypeLower := strings.ToLower(strings.TrimSpace(baseContentType))

			contentTypeMatched := false
			for _, expectedType := range r.ContentTypes {
				expectedTypeLower := strings.ToLower(strings.TrimSpace(expectedType))
				if baseContentTypeLower == expectedTypeLower || strings.Contains(baseContentTypeLower, expectedTypeLower) {
					contentTypeMatched = true
					break
				}
			}
			if !contentTypeMatched {
				return false
			}
		} else {
			return false
		}
	}

	// Match IP addresses
	if r.IP != nil && (len(r.IP.IPs) > 0 || len(r.IP.CIDRs) > 0 || len(r.IP.NotIn) > 0) {
		if !ctx.clientIPParsed {
			ctx.clientIP = getClientIP(req)
			ctx.clientIPParsed = true
		}
		if ctx.clientIP == "" {
			if len(r.IP.IPs) > 0 || len(r.IP.CIDRs) > 0 {
				return false
			}
		} else {
			if len(r.IP.NotIn) > 0 {
				if matchesIPOrCIDR(ctx.clientIP, r.IP.NotIn) {
					return false
				}
			}

			if len(r.IP.IPs) > 0 || len(r.IP.CIDRs) > 0 {
				ipsMatch := len(r.IP.IPs) > 0 && matchesIPOrCIDR(ctx.clientIP, r.IP.IPs)
				cidrsMatch := len(r.IP.CIDRs) > 0 && matchesIPOrCIDR(ctx.clientIP, r.IP.CIDRs)
				if !ipsMatch && !cidrsMatch {
					return false
				}
			}
		}
	}

	requestData := reqctx.GetRequestData(req.Context())

	// Match MaxMind location data
	if r.Location != nil {
		if !r.Location.match(requestData.Location) {
			return false
		}
	}

	// Match UAParser results
	if r.UserAgent != nil {
		if !r.UserAgent.match(requestData.UserAgent) {
			return false
		}
	}

	// Match user conditions
	if r.AuthConditions != nil {
		if requestData.SessionData == nil || requestData.SessionData.AuthData == nil {
			return false
		}
		if !r.AuthConditions.match(requestData.SessionData.AuthData) {
			return false
		}
	}

	// Match GraphQL query
	if r.GraphQL != nil {
		if !r.GraphQL.match(req) {
			return false
		}
	}

	// Match JSON body
	if r.JSON != nil {
		if !r.JSON.match(req) {
			return false
		}
	}

	// Match CEL expression
	if r.celexpr != nil {
		if !r.celexpr.Match(req) {
			return false
		}
	}

	// Match Lua script
	if r.luascript != nil {
		if !r.luascript.Match(req) {
			return false
		}
	}

	return true
}

// getClientIP extracts the client IP from the request
// It checks X-Real-IP, X-Forwarded-For, and RemoteAddr in that order
func getClientIP(req *http.Request) string {
	// Check X-Real-IP header first (highest precedence)
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Check X-Forwarded-For header (first IP in the list)
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Use RemoteAddr (extract IP from "host:port" format)
	if req.RemoteAddr != "" {
		host, _, err := net.SplitHostPort(req.RemoteAddr)
		if err == nil {
			return host
		}
		// If SplitHostPort fails, try to use RemoteAddr as-is (might be just IP)
		return req.RemoteAddr
	}

	return ""
}

// matchesIPOrCIDR checks if an IP matches any of the provided IPs or CIDR ranges
// It supports both individual IP addresses and CIDR notation for IPv4 and IPv6
func matchesIPOrCIDR(clientIP string, ipOrCIDRs []string) bool {
	clientIPParsed := net.ParseIP(clientIP)
	if clientIPParsed == nil {
		// Invalid IP format
		return false
	}

	for _, ipOrCIDR := range ipOrCIDRs {
		ipOrCIDR = strings.TrimSpace(ipOrCIDR)
		if ipOrCIDR == "" {
			continue
		}

		// Try to parse as CIDR first
		_, ipNet, err := net.ParseCIDR(ipOrCIDR)
		if err == nil {
			// It's a CIDR range
			if ipNet.Contains(clientIPParsed) {
				return true
			}
		} else {
			// Try to parse as individual IP
			ip := net.ParseIP(ipOrCIDR)
			if ip != nil {
				if ip.Equal(clientIPParsed) {
					return true
				}
			}
		}
	}

	return false
}

// match checks if MaxMind location data matches the rule criteria
// Uses case-insensitive matching for string fields
func (m *LocationConditions) match(location *reqctx.Location) bool {
	if location == nil {
		return false
	}

	// Match country codes (case-insensitive)
	if len(m.CountryCodes) > 0 {
		matched := false
		for _, code := range m.CountryCodes {
			if strings.EqualFold(code, location.CountryCode) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Match country names (case-insensitive)
	if len(m.Countries) > 0 {
		matched := false
		for _, country := range m.Countries {
			if strings.EqualFold(country, location.Country) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Match continent codes (case-insensitive)
	if len(m.ContinentCodes) > 0 {
		matched := false
		for _, code := range m.ContinentCodes {
			if strings.EqualFold(code, location.ContinentCode) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Match continent names (case-insensitive)
	if len(m.Continents) > 0 {
		matched := false
		for _, continent := range m.Continents {
			if strings.EqualFold(continent, location.Continent) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Match ASNs (exact match)
	if len(m.ASNs) > 0 {
		matched := false
		for _, asn := range m.ASNs {
			if asn == location.ASN {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Match AS names (case-insensitive)
	if len(m.ASNames) > 0 {
		matched := false
		for _, name := range m.ASNames {
			if strings.EqualFold(name, location.ASName) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Match AS domains (case-insensitive)
	if len(m.ASDomains) > 0 {
		matched := false
		for _, domain := range m.ASDomains {
			if strings.EqualFold(domain, location.ASDomain) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// match checks if UAParser results match the rule criteria
// Uses case-insensitive matching for string fields
func (u *UserAgentConditions) match(uaResult *reqctx.UserAgent) bool {
	if uaResult == nil {
		return false
	}

	// Match user agent families
	if len(u.UserAgentFamilies) > 0 {
		if uaResult.Family == "" {
			return false
		}
		matched := false
		for _, family := range u.UserAgentFamilies {
			if strings.EqualFold(family, uaResult.Family) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Match user agent major versions
	if len(u.UserAgentMajors) > 0 {
		if uaResult.Major == "" {
			return false
		}
		matched := false
		for _, major := range u.UserAgentMajors {
			if major == uaResult.Major {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Match user agent minor versions
	if len(u.UserAgentMinors) > 0 {
		if uaResult.Minor == "" {
			return false
		}
		matched := false
		for _, minor := range u.UserAgentMinors {
			if minor == uaResult.Minor {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Match OS families
	if len(u.OSFamilies) > 0 {
		if uaResult.OSFamily == "" {
			return false
		}
		matched := false
		for _, family := range u.OSFamilies {
			if strings.EqualFold(family, uaResult.OSFamily) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Match OS major versions
	if len(u.OSMajors) > 0 {
		if uaResult.OSMajor == "" {
			return false
		}
		matched := false
		for _, major := range u.OSMajors {
			if major == uaResult.OSMajor {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Match OS minor versions
	if len(u.OSMinors) > 0 {
		if uaResult.OSMinor == "" {
			return false
		}
		matched := false
		for _, minor := range u.OSMinors {
			if minor == uaResult.OSMinor {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Match device families
	if len(u.DeviceFamilies) > 0 {
		if uaResult.DeviceFamily == "" {
			return false
		}
		matched := false
		for _, family := range u.DeviceFamilies {
			if strings.EqualFold(family, uaResult.DeviceFamily) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Match device brands
	if len(u.DeviceBrands) > 0 {
		if uaResult.DeviceBrand == "" {
			return false
		}
		matched := false
		for _, brand := range u.DeviceBrands {
			if strings.EqualFold(brand, uaResult.DeviceBrand) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Match device models
	if len(u.DeviceModels) > 0 {
		if uaResult.DeviceModel == "" {
			return false
		}
		matched := false
		for _, model := range u.DeviceModels {
			if strings.EqualFold(model, uaResult.DeviceModel) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// detectProtocol detects the protocol from the request
func detectProtocol(req *http.Request) string {
	// Check for WebSocket upgrade
	if req.Header.Get("Upgrade") == "websocket" &&
		strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade") {
		return "websocket"
	}

	// Check for gRPC (content-type based)
	ct := req.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/grpc") {
		return "grpc"
	}

	// Check HTTP version
	if req.ProtoMajor == 3 {
		return "http3"
	}

	if req.ProtoMajor == 2 {
		// Check for bidirectional streaming indicators
		ae := req.Header.Get("Accept-Encoding")
		if ae == "identity" || ae == "" {
			ct := req.Header.Get("Content-Type")
			// Check for streaming content types or explicit streaming intent
			if strings.HasPrefix(ct, "application/x-ndjson") ||
				strings.HasPrefix(ct, "text/event-stream") ||
				strings.HasPrefix(ct, "application/stream+json") ||
				req.Header.Get("X-Stream-Mode") == "bidirectional" {
				return "http2_bidirectional"
			}
		}
		return "http2"
	}

	return "http1"
}

// matchProtocol checks if the detected protocol matches the rule protocol
func matchProtocol(ruleProtocol, detectedProtocol string) bool {
	// Handle generic "http" protocol (matches http1, http2, http3)
	if ruleProtocol == "http" {
		return detectedProtocol == "http1" || detectedProtocol == "http2" || detectedProtocol == "http3"
	}

	// Exact match
	return ruleProtocol == detectedProtocol
}

// getProtoVersion extracts the protocol version string from the request
func getProtoVersion(req *http.Request) string {
	if req.ProtoMajor == 3 {
		return "3.0"
	}
	if req.ProtoMajor == 2 {
		return "2.0"
	}
	if req.ProtoMajor == 1 {
		if req.ProtoMinor == 0 {
			return "1.0"
		}
		return "1.1"
	}
	// Default to 1.1 if unknown
	return "1.1"
}

// match checks if GraphQL query matches the rule criteria
func (g *GraphQLConditions) match(req *http.Request) bool {
	// Check Content-Type
	contentType := req.Header.Get("Content-Type")
	isGraphQL := strings.Contains(strings.ToLower(contentType), "application/json") ||
		strings.Contains(strings.ToLower(contentType), "application/graphql")

	if !isGraphQL {
		return false
	}

	// Parse GraphQL request
	gqlReq, err := parseGraphQLRequestFromHTTP(req)
	if err != nil {
		// Not a GraphQL request or parsing failed
		return false
	}

	// Match operation name
	if g.OperationName != "" {
		if gqlReq.OperationName != g.OperationName {
			return false
		}
	}

	if len(g.OperationNames) > 0 {
		matched := false
		for _, name := range g.OperationNames {
			if gqlReq.OperationName == name {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if g.OperationNameRegex != "" {
		matched, err := matchRegex(g.OperationNameRegex, gqlReq.OperationName)
		if err != nil || !matched {
			return false
		}
	}

	// Match query contains
	if g.QueryContains != "" {
		if !strings.Contains(gqlReq.Query, g.QueryContains) {
			return false
		}
	}

	// Parse query to extract operation type and fields
	if len(g.OperationTypes) > 0 || len(g.Fields) > 0 || len(g.FieldsAll) > 0 || g.FieldsRegex != "" {
		doc, err := parseGraphQLQuery(gqlReq.Query)
		if err != nil {
			// Can't parse query, so can't match operation type or fields
			return false
		}

		// Match operation types
		if len(g.OperationTypes) > 0 {
			opType := getOperationType(doc)
			matched := false
			for _, expectedType := range g.OperationTypes {
				if strings.EqualFold(opType, expectedType) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}

		// Extract field names
		fields := extractFieldNames(doc)

		// Match fields (any)
		if len(g.Fields) > 0 {
			matched := false
			for _, expectedField := range g.Fields {
				for _, field := range fields {
					if strings.EqualFold(field, expectedField) {
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
			if !matched {
				return false
			}
		}

		// Match fields (all)
		if len(g.FieldsAll) > 0 {
			fieldMap := make(map[string]bool)
			for _, field := range fields {
				fieldMap[strings.ToLower(field)] = true
			}
			for _, expectedField := range g.FieldsAll {
				if !fieldMap[strings.ToLower(expectedField)] {
					return false
				}
			}
		}

		// Match fields regex
		if g.FieldsRegex != "" {
			matched := false
			for _, field := range fields {
				m, err := matchRegex(g.FieldsRegex, field)
				if err == nil && m {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}

	return true
}

// parseGraphQLRequestFromHTTP parses a GraphQL request from HTTP request
func parseGraphQLRequestFromHTTP(req *http.Request) (*graphQLRequest, error) {
	gqlReq := &graphQLRequest{}

	// Check Content-Type
	contentType := req.Header.Get("Content-Type")
	isJSON := strings.Contains(strings.ToLower(contentType), "application/json")

	// Handle GET requests
	if req.Method == http.MethodGet {
		gqlReq.Query = req.URL.Query().Get("query")
		gqlReq.OperationName = req.URL.Query().Get("operationName")
		if gqlReq.Query == "" {
			return nil, fmt.Errorf("not a GraphQL request")
		}
		return gqlReq, nil
	}

	// Handle POST requests
	if req.Method == http.MethodPost && isJSON {
		// Read body
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read body: %w", err)
		}
		// Restore body
		req.Body = io.NopCloser(bytes.NewReader(body))

		// Try to parse as GraphQL request
		var gqlReqJSON struct {
			Query         string                 `json:"query"`
			OperationName string                 `json:"operationName,omitempty"`
			Variables     map[string]interface{} `json:"variables,omitempty"`
		}
		if err := json.Unmarshal(body, &gqlReqJSON); err != nil {
			return nil, fmt.Errorf("not a GraphQL request: %w", err)
		}

		if gqlReqJSON.Query == "" {
			return nil, fmt.Errorf("not a GraphQL request: query is empty")
		}

		gqlReq.Query = gqlReqJSON.Query
		gqlReq.OperationName = gqlReqJSON.OperationName
		return gqlReq, nil
	}

	return nil, fmt.Errorf("not a GraphQL request")
}

// graphQLRequest represents a parsed GraphQL request
type graphQLRequest struct {
	Query         string
	OperationName string
}

// parseGraphQLQuery parses a GraphQL query string into an AST document
func parseGraphQLQuery(query string) (*ast.Document, error) {
	src := source.NewSource(&source.Source{
		Body: []byte(query),
		Name: "GraphQL query",
	})

	doc, err := parser.Parse(parser.ParseParams{Source: src})
	if err != nil {
		return nil, err
	}

	return doc, nil
}

// getOperationType extracts the operation type from a GraphQL document
func getOperationType(doc *ast.Document) string {
	for _, def := range doc.Definitions {
		if op, ok := def.(*ast.OperationDefinition); ok {
			switch op.Operation {
			case ast.OperationTypeQuery:
				return "query"
			case ast.OperationTypeMutation:
				return "mutation"
			case ast.OperationTypeSubscription:
				return "subscription"
			default:
				// Default to query if not specified
				return "query"
			}
		}
	}
	// Default to query if no operation found
	return "query"
}

// extractFieldNames extracts all field names from a GraphQL document
func extractFieldNames(doc *ast.Document) []string {
	fields := make([]string, 0)
	seen := make(map[string]bool)

	for _, def := range doc.Definitions {
		if op, ok := def.(*ast.OperationDefinition); ok {
			extractFieldsFromSelection(op.SelectionSet, &fields, seen)
		}
	}

	return fields
}

// extractFieldsFromSelection recursively extracts field names from a selection set
func extractFieldsFromSelection(selectionSet *ast.SelectionSet, fields *[]string, seen map[string]bool) {
	if selectionSet == nil {
		return
	}

	for _, sel := range selectionSet.Selections {
		switch s := sel.(type) {
		case *ast.Field:
			fieldName := s.Name.Value
			if !seen[fieldName] {
				*fields = append(*fields, fieldName)
				seen[fieldName] = true
			}
			if s.SelectionSet != nil {
				extractFieldsFromSelection(s.SelectionSet, fields, seen)
			}
		case *ast.InlineFragment:
			if s.SelectionSet != nil {
				extractFieldsFromSelection(s.SelectionSet, fields, seen)
			}
		}
	}
}

// matchRegex matches a string against a regex pattern
func matchRegex(pattern, str string) (bool, error) {
	matched, err := regexp.MatchString(pattern, str)
	return matched, err
}

// match checks if JSON body matches the rule criteria
func (j *JSONConditions) match(req *http.Request) bool {
	// Check Content-Type
	contentType := req.Header.Get("Content-Type")
	isJSON := strings.Contains(strings.ToLower(contentType), "application/json") ||
		strings.Contains(strings.ToLower(contentType), "application/graphql")

	if !isJSON {
		return false
	}

	// Read body
	if req.Body == nil {
		return false
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return false
	}
	// Restore the body
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Match body contains
	if j.BodyContains != "" {
		if !strings.Contains(string(bodyBytes), j.BodyContains) {
			return false
		}
	}

	// Parse JSON
	var jsonData interface{}
	if err := json.Unmarshal(bodyBytes, &jsonData); err != nil {
		// Not valid JSON
		return false
	}

	// Extract all field paths from JSON
	fields := extractJSONFields(jsonData, "")

	// Match fields (any)
	if len(j.Fields) > 0 {
		matched := false
		for _, expectedField := range j.Fields {
			for _, field := range fields {
				if strings.EqualFold(field, expectedField) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Match fields (all)
	if len(j.FieldsAll) > 0 {
		fieldMap := make(map[string]bool)
		for _, field := range fields {
			fieldMap[strings.ToLower(field)] = true
		}
		for _, expectedField := range j.FieldsAll {
			if !fieldMap[strings.ToLower(expectedField)] {
				return false
			}
		}
	}

	// Match fields regex
	if j.FieldsRegex != "" {
		matched := false
		for _, field := range fields {
			if m, err := matchRegex(j.FieldsRegex, field); err == nil && m {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Match field values
	if len(j.FieldValue) > 0 {
		for path, expectedValue := range j.FieldValue {
			actualValue := getJSONValue(jsonData, path)
			if actualValue == nil || fmt.Sprintf("%v", actualValue) != expectedValue {
				return false
			}
		}
	}

	// Match field value in list
	if len(j.FieldValueIn) > 0 {
		for path, expectedValues := range j.FieldValueIn {
			actualValue := getJSONValue(jsonData, path)
			if actualValue == nil {
				return false
			}
			actualValueStr := fmt.Sprintf("%v", actualValue)
			matched := false
			for _, expectedValue := range expectedValues {
				if actualValueStr == expectedValue {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}

	// Match field value regex
	if len(j.FieldValueRegex) > 0 {
		for path, pattern := range j.FieldValueRegex {
			actualValue := getJSONValue(jsonData, path)
			if actualValue == nil {
				return false
			}
			actualValueStr := fmt.Sprintf("%v", actualValue)
			if matched, err := matchRegex(pattern, actualValueStr); err != nil || !matched {
				return false
			}
		}
	}

	return true
}

// extractJSONFields extracts all field paths from JSON data
func extractJSONFields(data interface{}, prefix string) []string {
	fields := make([]string, 0)
	extractJSONFieldsRecursive(data, prefix, &fields, make(map[string]bool))
	return fields
}

// extractJSONFieldsRecursive recursively extracts field paths
func extractJSONFieldsRecursive(data interface{}, prefix string, fields *[]string, seen map[string]bool) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			fieldPath := key
			if prefix != "" {
				fieldPath = prefix + "." + key
			}
			fieldPathLower := strings.ToLower(fieldPath)
			if !seen[fieldPathLower] {
				*fields = append(*fields, fieldPath)
				seen[fieldPathLower] = true
			}
			extractJSONFieldsRecursive(value, fieldPath, fields, seen)
		}
	case []interface{}:
		for i, item := range v {
			fieldPath := fmt.Sprintf("[%d]", i)
			if prefix != "" {
				fieldPath = prefix + fieldPath
			}
			extractJSONFieldsRecursive(item, fieldPath, fields, seen)
		}
	}
}

// getJSONValue gets a value from JSON using dot notation path
func getJSONValue(data interface{}, path string) interface{} {
	if path == "" {
		return data
	}

	parts := strings.Split(path, ".")
	current := data

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			var ok bool
			current, ok = v[part]
			if !ok {
				return nil
			}
		case []interface{}:
			// Array access - try to parse index
			// For now, skip array access in dot notation
			return nil
		default:
			return nil
		}
	}

	return current
}
