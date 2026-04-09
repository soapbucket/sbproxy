// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
package util

// HTTP Headers used across the proxy
const (
	// Custom headers for proxy functionality
	HeaderOrigin      = "x-sb-origin"
	// HeaderOptional is the HTTP header name for optional.
	HeaderOptional    = "x-sb-optional"
	// HeaderSessionID is the HTTP header name for session id.
	HeaderSessionID   = "x-sb-session"
	// HeaderFlags is the HTTP header name for flags.
	HeaderFlags       = "x-sb-flags"
	// HeaderRequestID is the HTTP header name for request id.
	HeaderRequestID   = "x-sb-id"
	// HeaderFingerprint is the HTTP header name for fingerprint.
	HeaderFingerprint = "x-sb-fingerprint"
	// HeaderUserAgent is the HTTP header name for user agent.
	HeaderUserAgent   = "x-sb-ua"
	// HeaderTiming is the HTTP header name for timing.
	HeaderTiming      = "x-sb-timing"
	// HeaderSB is the HTTP header name for sb.
	HeaderSB          = "x-sb"

	// Standard HTTP headers
	HeaderVary            = "Vary"
	// HeaderCacheControl is the HTTP header name for cache control.
	HeaderCacheControl    = "Cache-Control"
	// HeaderContentType is the HTTP header name for content type.
	HeaderContentType     = "Content-Type"
	// HeaderContentEncoding is the HTTP header name for content encoding.
	HeaderContentEncoding = "Content-Encoding"
	// HeaderAcceptEncoding is the HTTP header name for accept encoding.
	HeaderAcceptEncoding  = "Accept-Encoding"
	// HeaderLocation is the HTTP header name for location.
	HeaderLocation        = "Location"
	// HeaderETag is the HTTP header name for e tag.
	HeaderETag            = "ETag"
	// HeaderLastModified is the HTTP header name for last modified.
	HeaderLastModified    = "Last-Modified"
	// HeaderIfModifiedSince is the HTTP header name for if modified since.
	HeaderIfModifiedSince = "If-Modified-Since"
	// HeaderIfNoneMatch is the HTTP header name for if none match.
	HeaderIfNoneMatch     = "If-None-Match"
)

// Cache control directives
const (
	// CacheControlNoCache is a constant for cache control no cache.
	CacheControlNoCache        = "no-cache"
	// CacheControlNoStore is a constant for cache control no store.
	CacheControlNoStore        = "no-store"
	// CacheControlMaxAge is a constant for cache control max age.
	CacheControlMaxAge         = "max-age"
	// CacheControlSMaxAge is a constant for cache control s max age.
	CacheControlSMaxAge        = "s-maxage"
	// CacheControlPublic is a constant for cache control public.
	CacheControlPublic         = "public"
	// CacheControlPrivate is a constant for cache control private.
	CacheControlPrivate        = "private"
	// CacheControlMustRevalidate is a constant for cache control must revalidate.
	CacheControlMustRevalidate = "must-revalidate"
)

// Content types
const (
	// ContentTypeJSON is a constant for content type json.
	ContentTypeJSON        = "application/json"
	// ContentTypeHTML is a constant for content type html.
	ContentTypeHTML        = "text/html"
	// ContentTypeXML is a constant for content type xml.
	ContentTypeXML         = "application/xml"
	// ContentTypeText is a constant for content type text.
	ContentTypeText        = "text/plain"
	// ContentTypeOctetStream is a constant for content type octet stream.
	ContentTypeOctetStream = "application/octet-stream"
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
