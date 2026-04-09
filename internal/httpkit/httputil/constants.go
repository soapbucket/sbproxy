// Package httputil defines HTTP constants, header names, and shared request/response utilities.
package httputil

// HTTP Header Constants
// This package provides constants for all HTTP headers used throughout the Soapbucket Proxy.
// Using these constants prevents typos, provides IDE autocomplete, and ensures consistency.

// Standard HTTP Headers
const (
	// Request Headers
	HeaderAccept          = "Accept"
	// HeaderAcceptEncoding is the HTTP header name for accept encoding.
	HeaderAcceptEncoding  = "Accept-Encoding"
	// HeaderAcceptLanguage is the HTTP header name for accept language.
	HeaderAcceptLanguage  = "Accept-Language"
	// HeaderAuthorization is the HTTP header name for authorization.
	HeaderAuthorization   = "Authorization"
	// HeaderCacheControl is the HTTP header name for cache control.
	HeaderCacheControl    = "Cache-Control"
	// HeaderConnection is the HTTP header name for connection.
	HeaderConnection      = "Connection"
	// HeaderContentEncoding is the HTTP header name for content encoding.
	HeaderContentEncoding = "Content-Encoding"
	// HeaderContentLength is the HTTP header name for content length.
	HeaderContentLength   = "Content-Length"
	// HeaderContentType is the HTTP header name for content type.
	HeaderContentType     = "Content-Type"
	// HeaderCookie is the HTTP header name for cookie.
	HeaderCookie          = "Cookie"
	// HeaderHost is the HTTP header name for host.
	HeaderHost            = "Host"
	// HeaderIfModifiedSince is the HTTP header name for if modified since.
	HeaderIfModifiedSince = "If-Modified-Since"
	// HeaderIfNoneMatch is the HTTP header name for if none match.
	HeaderIfNoneMatch     = "If-None-Match"
	// HeaderOrigin is the HTTP header name for origin.
	HeaderOrigin          = "Origin"
	// HeaderReferer is the HTTP header name for referer.
	HeaderReferer         = "Referer"
	// HeaderUserAgent is the HTTP header name for user agent.
	HeaderUserAgent       = "User-Agent"

	// Response Headers
	HeaderDate         = "Date"
	// HeaderETag is the HTTP header name for e tag.
	HeaderETag         = "ETag"
	// HeaderExpires is the HTTP header name for expires.
	HeaderExpires      = "Expires"
	// HeaderLastModified is the HTTP header name for last modified.
	HeaderLastModified = "Last-Modified"
	// HeaderSetCookie is the HTTP header name for set cookie.
	HeaderSetCookie    = "Set-Cookie"

	// Proxy Headers
	HeaderXForwardedFor   = "X-Forwarded-For"
	// HeaderXForwardedHost is the HTTP header name for x forwarded host.
	HeaderXForwardedHost  = "X-Forwarded-Host"
	// HeaderXForwardedProto is the HTTP header name for x forwarded proto.
	HeaderXForwardedProto = "X-Forwarded-Proto"
	// HeaderXRealIP is the HTTP header name for x real ip.
	HeaderXRealIP         = "X-Real-IP"
	// HeaderXRequestID is the HTTP header name for x request id.
	HeaderXRequestID      = "X-Request-ID"

	// SoapBucket Custom Headers
	HeaderXSbFingerprint      = "X-Sb-Fingerprint"
	// HeaderXSbFingerprintDebug is the HTTP header name for x sb fingerprint debug.
	HeaderXSbFingerprintDebug = "X-Sb-Fingerprint-Debug"
	// HeaderXSbFlags is the HTTP header name for x sb flags.
	HeaderXSbFlags            = "X-Sb-Flags"
	// HeaderXSbDebug is the HTTP header name for x sb debug.
	HeaderXSbDebug            = "X-Sb-Debug"
	// HeaderXSbUserAgent is the HTTP header name for x sb user agent.
	HeaderXSbUserAgent        = "X-Sb-User-Agent"
	// HeaderxSbMaxMind is the HTTP header name for x sb max mind.
	HeaderxSbMaxMind          = "X-Sb-Ip-Info"
	// HeaderXSbRequestID is the HTTP header name for x sb request id.
	HeaderXSbRequestID        = "X-Sb-Id"
	// HeaderXSbTransform is the HTTP header name for x sb transform.
	HeaderXSbTransform        = "X-Sb"
	// HeaderXSbVersion is the HTTP header name for x sb version.
	HeaderXSbVersion          = "X-Sb-Version"
	// HeaderXSbBuildHash is the HTTP header name for x sb build hash.
	HeaderXSbBuildHash        = "X-Sb-Build-Hash"
	// HeaderXSbOriginConfig is the HTTP header name for x sb origin config.
	HeaderXSbOriginConfig     = "X-Sb-Origin-Config"
	// HeaderXSbOrigin is the HTTP header name for x sb origin.
	HeaderXSbOrigin           = "X-Sb-Origin"
	// HeaderXSbConfigMode is the HTTP header name for x sb config mode.
	HeaderXSbConfigMode       = "X-Sb-Config-Mode"
	// HeaderXSbConfigReason is the HTTP header name for x sb config reason.
	HeaderXSbConfigReason     = "X-Sb-Config-Reason"
	// HeaderXSbConfigVersion is the HTTP header name for x sb config version.
	HeaderXSbConfigVersion    = "X-Sb-Config-Version"
	// HeaderXSbConfigRevision is the HTTP header name for x sb config revision.
	HeaderXSbConfigRevision   = "X-Sb-Config-Revision"
	// HeaderXSbCacheKey is the HTTP header name for x sb cache key.
	HeaderXSbCacheKey         = "X-Sb-Cache-Key"
	// HeaderXSbAIModel is the HTTP header name for x sb ai model.
	HeaderXSbAIModel          = "X-Sb-Ai-Model"
	// HeaderXSbAIProvider is the HTTP header name for x sb ai provider.
	HeaderXSbAIProvider       = "X-Sb-Ai-Provider"

	// W3C Trace Context Headers
	HeaderTraceparent = "Traceparent"
	// HeaderTracestate is the W3C Trace Context tracestate header.
	HeaderTracestate = "Tracestate"

	// Security Headers
	HeaderXChallengeResponse = "X-Challenge-Response"

	// Other Headers
	HeaderAltSvc      = "Alt-Svc"
	// HeaderVary is the HTTP header name for vary.
	HeaderVary        = "Vary"
	// HeaderLargeHeader is the HTTP header name for large header.
	HeaderLargeHeader = "LargeHeader" // Used in tests
)

// Load Balancer Cookie Names
const (
	// Default load balancer sticky session cookie names
	DefaultStickyCookieName = "_sb.l" // SoapBucket Load balancer
)

// Content Types
const (
	// ContentTypeJSON is a constant for content type json.
	ContentTypeJSON           = "application/json"
	// ContentTypeFormURLEncoded is a constant for content type form url encoded.
	ContentTypeFormURLEncoded = "application/x-www-form-urlencoded"
	// ContentTypeHTML is a constant for content type html.
	ContentTypeHTML           = "text/html"
	// ContentTypeXML is a constant for content type xml.
	ContentTypeXML            = "application/xml"
	// ContentTypeText is a constant for content type text.
	ContentTypeText           = "text/plain"
	// ContentTypeOctetStream is a constant for content type octet stream.
	ContentTypeOctetStream    = "application/octet-stream"
)

// Cache Control Values
const (
	// CacheControlNoCache is a constant for cache control no cache.
	CacheControlNoCache = "no-cache"
	// CacheControlNoStore is a constant for cache control no store.
	CacheControlNoStore = "no-store"
	// CacheControlPrivate is a constant for cache control private.
	CacheControlPrivate = "private"
	// CacheControlPublic is a constant for cache control public.
	CacheControlPublic  = "public"
	// CacheControlMaxAge is a constant for cache control max age.
	CacheControlMaxAge  = "max-age"
)

// User Agent Values
const (
	// UserAgentSoapBucket is a constant for user agent soap bucket.
	UserAgentSoapBucket  = "soapbucket-proxy/1.0"
	// UserAgentMozilla is a constant for user agent mozilla.
	UserAgentMozilla     = "Mozilla/5.0"
	// UserAgentTest is a constant for user agent test.
	UserAgentTest        = "Test-Browser/1.0"
	// UserAgentIntegration is a constant for user agent integration.
	UserAgentIntegration = "Integration-Test/1.0"
	// UserAgentBenchmark is a constant for user agent benchmark.
	UserAgentBenchmark   = "Benchmark-Test/1.0"
)

// Common Header Values
const (
	// ConnectionKeepAlive is a constant for connection keep alive.
	ConnectionKeepAlive = "keep-alive"
	// AcceptAll is a constant for accept all.
	AcceptAll           = "*/*"
	// AcceptHTML is a constant for accept html.
	AcceptHTML          = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	// AcceptJSON is a constant for accept json.
	AcceptJSON          = "application/json"
	// AcceptEncodingGzip is a constant for accept encoding gzip.
	AcceptEncodingGzip  = "gzip, deflate"
	// AcceptLanguageEn is a constant for accept language en.
	AcceptLanguageEn    = "en-US,en;q=0.5"
)

const (
	// HttpStatusUnknownError is a constant for http status unknown error.
	HttpStatusUnknownError          = 520
	// HttpStatusWebServerDown is a constant for http status web server down.
	HttpStatusWebServerDown         = 521
	// HttpStatusConnectionTimeout is a constant for http status connection timeout.
	HttpStatusConnectionTimeout     = 522
	// HttpStatusOriginUnreachable is a constant for http status origin unreachable.
	HttpStatusOriginUnreachable     = 523
	// HttpStatusTimeoutOccured is a constant for http status timeout occured.
	HttpStatusTimeoutOccured        = 524
	// HttpStatusSSLHandshakeFailed is a constant for http status ssl handshake failed.
	HttpStatusSSLHandshakeFailed    = 525
	// HttpStatusInvalidSSLCertificate is a constant for http status invalid ssl certificate.
	HttpStatusInvalidSSLCertificate = 526
	// HttpStatusDown is a constant for http status down.
	HttpStatusDown                  = 530
)
