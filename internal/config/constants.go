// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import "time"

const (
	// APIEndpoint is a constant for api endpoint.
	APIEndpoint = "/_sb/api/"

	// DefaultCacheDuration is the default value for cache duration.
	DefaultCacheDuration = 1 * time.Hour

	// EmptyGIF1x1 is a 1x1 transparent GIF image (43 bytes)
	// Used for tracking pixels and beacons
	EmptyGIF1x1 = "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"

	// TypeBeacon is a constant for type beacon.
	TypeBeacon        = "beacon"
	// TypeNoop is a constant for type noop.
	TypeNoop          = "noop"
	// TypeProxy is a constant for type proxy.
	TypeProxy         = "proxy"
	// TypeRedirect is a constant for type redirect.
	TypeRedirect      = "redirect"
	// TypeStorage is a constant for type storage.
	TypeStorage       = "storage"
	// TypeStatic is a constant for type static.
	TypeStatic        = "static"
	// TypeOrchestration is a constant for type orchestration.
	TypeOrchestration = "orchestration"
	// TypeNone is a constant for type none.
	TypeNone          = ""
	// TypeEcho is a constant for type echo.
	TypeEcho          = "echo"
	// TypeLoadBalancer is a constant for type load balancer.
	TypeLoadBalancer  = "loadbalancer"
	// TypeWebSocket is a constant for type web socket.
	TypeWebSocket     = "websocket"
	// TypeGraphQL is a constant for type graph ql.
	TypeGraphQL       = "graphql"
	// TypeGRPC is a constant for type grpc.
	TypeGRPC          = "grpc"
	// TypeABTest is a constant for type ab test.
	TypeABTest        = "abtest"
	// TypeMCP is a constant for type mcp.
	TypeMCP           = "mcp"
	// TypeAIProxy is a constant for type ai proxy.
	TypeAIProxy       = "ai_proxy"
	// TypeA2A is a constant for type a2a.
	TypeA2A           = "a2a"
	// TypeHTTPSProxy is a constant for type https proxy.
	TypeHTTPSProxy    = "https_proxy"
	// TypeWasm is a constant for type wasm.
	TypeWasm          = "wasm"
	// TypeMock is a constant for type mock.
	TypeMock          = "mock"

	// Circuit breaker states
	CircuitBreakerStateClosed   = "closed"
	// CircuitBreakerStateOpen is a constant for circuit breaker state open.
	CircuitBreakerStateOpen     = "open"
	// CircuitBreakerStateHalfOpen is a constant for circuit breaker state half open.
	CircuitBreakerStateHalfOpen = "half_open"

	// Circuit breaker defaults
	DefaultCircuitBreakerFailureThreshold       = 5
	// DefaultCircuitBreakerSuccessThreshold is the default value for circuit breaker success threshold.
	DefaultCircuitBreakerSuccessThreshold       = 2
	// DefaultCircuitBreakerRequestVolumeThreshold is the default value for circuit breaker request volume threshold.
	DefaultCircuitBreakerRequestVolumeThreshold = 10
	// DefaultCircuitBreakerTimeout is the default value for circuit breaker timeout.
	DefaultCircuitBreakerTimeout                = 30 * time.Second
	// DefaultCircuitBreakerErrorRateThreshold is the default value for circuit breaker error rate threshold.
	DefaultCircuitBreakerErrorRateThreshold     = 0.5 // 50%
	// DefaultCircuitBreakerHalfOpenRequests is the default value for circuit breaker half open requests.
	DefaultCircuitBreakerHalfOpenRequests       = 3

	// Load balancer algorithm constants
	// AlgorithmWeightedRandom selects targets randomly, weighted by their weight field (default).
	AlgorithmWeightedRandom = "weighted_random"
	// AlgorithmRoundRobin selects targets in sequential order.
	AlgorithmRoundRobin = "round_robin"
	// AlgorithmWeightedRoundRobin selects targets in sequential order, proportional to weight.
	AlgorithmWeightedRoundRobin = "weighted_round_robin"
	// AlgorithmLeastConnections selects the target with the fewest active connections.
	AlgorithmLeastConnections = "least_connections"
	// AlgorithmIPHash hashes the client IP for consistent routing; same IP always goes to same backend.
	AlgorithmIPHash = "ip_hash"
	// AlgorithmURIHash hashes the request URL path for consistent routing; same path goes to same backend.
	AlgorithmURIHash = "uri_hash"
	// AlgorithmHeaderHash hashes a specified request header value (requires hash_key config field).
	AlgorithmHeaderHash = "header_hash"
	// AlgorithmCookieHash hashes a specified cookie value (requires hash_key config field).
	AlgorithmCookieHash = "cookie_hash"
	// AlgorithmRandom selects a target with equal probability (ignores weights).
	AlgorithmRandom = "random"
	// AlgorithmFirst selects the first healthy target in list order (primary/failover pattern).
	AlgorithmFirst = "first"

	// DefaultStickyCookieName is the default name for sticky session cookie
	DefaultStickyCookieName = "_sb.l"
	// DefaultStickyCookieMaxAge is the default max age for sticky cookie (1 hour)
	DefaultStickyCookieMaxAge = 3600

	// Default health check settings
	DefaultHealthCheckInterval = 10 * time.Second
	// DefaultHealthCheckTimeout is the default value for health check timeout.
	DefaultHealthCheckTimeout  = 5 * time.Second
	// DefaultHealthCheckPath is the default value for health check path.
	DefaultHealthCheckPath     = "/"
	// DefaultHealthCheckMethod is the default value for health check method.
	DefaultHealthCheckMethod   = "GET"
	// DefaultHealthyThreshold is the default value for healthy threshold.
	DefaultHealthyThreshold    = 2
	// DefaultUnhealthyThreshold is the default value for unhealthy threshold.
	DefaultUnhealthyThreshold  = 2

	// TransformEncoding is a constant for transform encoding.
	TransformEncoding       = "encoding"
	// TransformJSON is a constant for transform json.
	TransformJSON           = "json"
	// TransformHTML is a constant for transform html.
	TransformHTML           = "html"
	// TransformOptimizedHTML is a constant for transform optimized html.
	TransformOptimizedHTML  = "optimized_html"
	// TransformNoop is a constant for transform noop.
	TransformNoop           = "noop"
	// TransformReplaceStrings is a constant for transform replace strings.
	TransformReplaceStrings = "replace_strings"
	// TransformNone is a constant for transform none.
	TransformNone           = ""
	// TransformDiscard is a constant for transform discard.
	TransformDiscard        = "discard"
	// TransformJavascript is a constant for transform javascript.
	TransformJavascript     = "javascript"
	// TransformCSS is a constant for transform css.
	TransformCSS            = "css"
	// TransformTemplate is a constant for transform template.
	TransformTemplate           = "template"
	// TransformMarkdown is a constant for transform markdown.
	TransformMarkdown           = "markdown"
	// TransformHTMLToMarkdown is a constant for transform html to markdown.
	TransformHTMLToMarkdown     = "html_to_markdown"
	// TransformLuaJSON is a constant for transform lua json.
	TransformLuaJSON            = "lua_json"
	// TransformWasm is a constant for transform wasm.
	TransformWasm               = "wasm"

	// AI Gateway transform types
	TransformJSONSchema     = "json_schema"
	// TransformJSONProjection is a constant for transform json projection.
	TransformJSONProjection = "json_projection"
	// TransformPayloadLimit is a constant for transform payload limit.
	TransformPayloadLimit   = "payload_limit"
	// TransformFormatConvert is a constant for transform format convert.
	TransformFormatConvert  = "format_convert"
	// TransformClassify is a constant for transform classify.
	TransformClassify       = "classify"
	// TransformTokenCount is a constant for transform token count.
	TransformTokenCount     = "token_count"
	// TransformAISchema is a constant for transform ai schema.
	TransformAISchema       = "ai_schema"
	// TransformAICache is a constant for transform ai cache.
	TransformAICache        = "ai_cache"
	// TransformSSEChunking is a constant for transform sse chunking.
	TransformSSEChunking    = "sse_chunking"
	// TransformNormalize is a constant for transform normalize.
	TransformNormalize       = "normalize"
	// TransformSidecarClassify is a constant for transform sidecar classify.
	TransformSidecarClassify = "sidecar_classify"

	// AuthTypeJWT is a constant for auth type jwt.
	AuthTypeJWT         = "jwt"
	// AuthTypeOAuth is a constant for auth type o auth.
	AuthTypeOAuth       = "oauth"
	// AuthTypeAPIKey is a constant for auth type api key.
	AuthTypeAPIKey      = "api_key"
	// AuthTypeBasicAuth is a constant for auth type basic auth.
	AuthTypeBasicAuth   = "basic_auth"
	// AuthTypeBearerToken is a constant for auth type bearer token.
	AuthTypeBearerToken = "bearer_token"
	// AuthTypeNone is a constant for auth type none.
	AuthTypeNone        = ""
	// AuthTypeNoop is a constant for auth type noop.
	AuthTypeNoop        = "noop"
	// AuthTypeOAuthIntrospection is a constant for auth type oauth introspection.
	AuthTypeOAuthIntrospection = "oauth_introspection"
	// AuthTypeOAuthClientCredentials is a constant for auth type oauth client credentials.
	AuthTypeOAuthClientCredentials = "oauth_client_credentials"
	// AuthTypeForward is a constant for auth type forward.
	AuthTypeForward     = "forward"
	// AuthTypeGRPCAuth is a constant for auth type grpc external auth.
	AuthTypeGRPCAuth    = "grpc_auth"

	// PolicyTypeRequestSigning is a constant for policy type request signing.
	PolicyTypeRequestSigning  = "request_signing"
	// PolicyTypeIPFiltering is a constant for policy type ip filtering.
	PolicyTypeIPFiltering     = "ip_filtering"
	// PolicyTypeSecurityHeaders is a constant for policy type security headers.
	PolicyTypeSecurityHeaders = "security_headers"
	// PolicyTypeRateLimiting is a constant for policy type rate limiting.
	PolicyTypeRateLimiting    = "rate_limiting"
	// PolicyTypeRequestLimiting is a constant for policy type request limiting.
	PolicyTypeRequestLimiting = "request_limiting"
	// PolicyTypeThreatDetection is a constant for policy type threat detection.
	PolicyTypeThreatDetection = "threat_detection"
	// PolicyTypeDDoSProtection is a constant for policy type d do s protection.
	PolicyTypeDDoSProtection  = "ddos_protection"
	// PolicyTypeExpression is a constant for policy type expression.
	PolicyTypeExpression      = "expression"
	// PolicyTypeCSRF is a constant for policy type csrf.
	PolicyTypeCSRF            = "csrf"
	// PolicyTypeGeoBlocking is a constant for policy type geo blocking.
	PolicyTypeGeoBlocking     = "geo_blocking"
	// PolicyTypeSRI is a constant for policy type sri.
	PolicyTypeSRI             = "sri"
	// PolicyTypeWAF is a constant for policy type waf.
	PolicyTypeWAF             = "waf"
	// PolicyTypePII is a constant for policy type pii.
	PolicyTypePII             = "pii"
	// PolicyTypeFaultInjection is a constant for policy type fault injection.
	PolicyTypeFaultInjection  = "fault_injection"
	// PolicyTypeWasm is a constant for policy type wasm.
	PolicyTypeWasm            = "wasm"
)

// HTMLContentTypes is a variable for html content types.
var HTMLContentTypes = []string{
	"text/html",
}

// JSONContentTypes is a variable for json content types.
var JSONContentTypes = []string{
	"application/json",
	"application/ld+json",
	"application/schema+json",
	"application/geo+json",
}
// CSSContentTypes is a variable for css content types.
var CSSContentTypes = []string{
	"text/css",
}

// JavaScriptContentTypes is a variable for java script content types.
var JavaScriptContentTypes = []string{
	"text/javascript",
	"application/javascript",
	"application/ecmascript",
	"application/x-javascript",
	"application/x-ecmascript",
	"application/json",
	"application/ld+json",
	"application/schema+json",
	"application/geo+json",
}

// MarkdownContentTypes is a variable for markdown content types.
var MarkdownContentTypes = []string{
	"text/markdown",
	"text/x-markdown",
}

// TextContentTypes is a variable for text content types.
var TextContentTypes = append(append(append(HTMLContentTypes, JSONContentTypes...), CSSContentTypes...), JavaScriptContentTypes...)
