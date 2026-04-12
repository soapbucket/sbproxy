// Package httputil defines HTTP constants, header names, and shared request/response utilities.
package httputil

// Header Groups for common operations
var (
	// Security Headers - headers that should be preserved for security
	SecurityHeaders = []string{
		HeaderAuthorization,
		HeaderXForwardedFor,
		HeaderXForwardedHost,
		HeaderXForwardedProto,
		HeaderXRealIP,
		HeaderXRequestID,
		HeaderXChallengeResponse,
	}

	// Cache Headers - headers related to caching
	CacheHeaders = []string{
		HeaderCacheControl,
		HeaderETag,
		HeaderLastModified,
		HeaderIfModifiedSince,
		HeaderIfNoneMatch,
		HeaderExpires,
		HeaderDate,
	}

	// Content Headers - headers that describe content
	ContentHeaders = []string{
		HeaderContentType,
		HeaderContentEncoding,
		HeaderContentLength,
	}

	// Request Headers - common request headers
	RequestHeaders = []string{
		HeaderAccept,
		HeaderAcceptEncoding,
		HeaderAcceptLanguage,
		HeaderAuthorization,
		HeaderCacheControl,
		HeaderConnection,
		HeaderContentType,
		HeaderCookie,
		HeaderHost,
		HeaderIfModifiedSince,
		HeaderIfNoneMatch,
		HeaderOrigin,
		HeaderReferer,
		HeaderUserAgent,
		HeaderXForwardedFor,
		HeaderXForwardedHost,
		HeaderXForwardedProto,
		HeaderXRealIP,
		HeaderXRequestID,
	}

	// Response Headers - common response headers
	ResponseHeaders = []string{
		HeaderCacheControl,
		HeaderContentType,
		HeaderContentEncoding,
		HeaderContentLength,
		HeaderDate,
		HeaderETag,
		HeaderExpires,
		HeaderLastModified,
		HeaderSetCookie,
		HeaderXSbTransform,
	}

	// SoapBucketHeaders is a variable for soap bucket headers.
	SoapBucketHeaders = []string{
		HeaderXSbVersion,
		HeaderXSbDebug,
		HeaderXSbFlags,
		HeaderXSbUserAgent,
		HeaderXSbGeoIP,
		HeaderXSbRequestID,
		HeaderXSbTransform,
		HeaderXSbVersion,
		HeaderXSbOriginConfig,
		HeaderXSbFingerprint,
		HeaderXSbCacheKey,
	}
)

// IsSecurityHeader checks if a header name is considered a security-related header
func IsSecurityHeader(headerName string) bool {
	for _, securityHeader := range SecurityHeaders {
		if headerName == securityHeader {
			return true
		}
	}
	return false
}

// IsCacheHeader checks if a header name is related to caching
func IsCacheHeader(headerName string) bool {
	for _, cacheHeader := range CacheHeaders {
		if headerName == cacheHeader {
			return true
		}
	}
	return false
}

// IsContentHeader checks if a header name describes content
func IsContentHeader(headerName string) bool {
	for _, contentHeader := range ContentHeaders {
		if headerName == contentHeader {
			return true
		}
	}
	return false
}
