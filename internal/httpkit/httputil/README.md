# HTTPUtil Package

This package provides constants and utilities for all HTTP-related functionality used throughout the Soapbucket Proxy codebase.

## Overview

The httputil package centralizes all HTTP-related functionality including:
- HTTP header constants to prevent typos and ensure consistency
- Content type constants for standardized MIME types
- User agent constants for consistent user agent strings
- HTTP caching utilities following RFC 7234 specifications
- **Security validation and input sanitization** (NEW)
- Helper functions for header categorization and validation
- Future HTTP utility functions as the package expands

## Usage

### Basic Header Constants

```go
import "github.com/soapbucket/sbproxy/internal/httpkit/httputil"

// Use constants instead of hardcoded strings
req.Header.Set(httputil.HeaderContentType, httputil.ContentTypeJSON)
req.Header.Get(httputil.HeaderAuthorization)
req.Header.Add(httputil.HeaderSetCookie, cookieValue)
```

### Content Type Constants

```go
// Set content type
req.Header.Set(http.ContentType, http.ContentTypeJSON)
resp.Header.Set(http.ContentType, http.ContentTypeHTML)

// Check content type
if req.Header.Get(http.ContentType) == http.ContentTypeFormURLEncoded {
    // Handle form data
}
```

### Security Headers

```go
// Security-related headers
req.Header.Get(http.XForwardedFor)
req.Header.Get(http.XRealIP)
req.Header.Get(http.Authorization)
req.Header.Set(http.XRequestID, requestID)
```

### Cache Headers

```go
// Cache-related headers
req.Header.Get(http.IfNoneMatch)
req.Header.Get(http.IfModifiedSince)
resp.Header.Set(http.ETag, etagValue)
resp.Header.Set(http.CacheControl, http.CacheControlNoCache)
```

## HTTP Caching Utilities

The package provides comprehensive HTTP caching utilities following RFC 7234:

### Cacheable Check
```go
// Check if a request is cacheable
if httputil.IsCacheable(req) {
    // Request can be cached
}
```

### Cache Key Generation
```go
// Generate a cache key from request
key := httputil.GenerateCacheKey(req)
```

### Cache Duration Calculation
```go
// Calculate how long content can be cached
cached := httputil.CalculateCacheDuration(resp)
```

### Cache Validation
```go
// Check if cached response is still valid
valid, stale := httputil.IsCacheValid(req, cached)
if valid {
    // Serve fresh content
} else if stale {
    // Serve stale content while revalidating
}
```

### CachedResponse Structure
```go
type CachedResponse struct {
    Expires       time.Time     // When the cache entry expires
    StaleDuration time.Duration // How long to serve stale content
    ETag          string        // ETag for validation
    LastModified  time.Time     // Last-Modified timestamp
    MaxAge        int           // Max age in seconds
    MustRevalidate bool         // Must revalidate directive
    NoCache       bool          // No-cache directive
    NoStore       bool          // No-store directive
    Private       bool          // Private directive
    Public        bool          // Public directive
    VaryHeaders   []string      // Vary headers that affect cache key
    StatusCode    int           // Response status code
    Headers       map[string]string // Response headers
    Size          int64         // Response size
}
```

## Header Groups

The package provides helper functions to categorize headers:

```go
// Check if a header is security-related
if http.IsSecurityHeader("Authorization") {
    // Handle security header
}

// Check if a header is cache-related
if http.IsCacheHeader("ETag") {
    // Handle cache header
}

// Check if a header describes content
if http.IsContentHeader("Content-Type") {
    // Handle content header
}
```

## Available Header Groups

- `SecurityHeaders` - Headers that should be preserved for security
- `CacheHeaders` - Headers related to caching
- `ContentHeaders` - Headers that describe content
- `RequestHeaders` - Common request headers
- `ResponseHeaders` - Common response headers

## Migration from Hardcoded Strings

### Before
```go
req.Header.Set("Content-Type", "application/json")
req.Header.Get("Authorization")
resp.Header.Add("Set-Cookie", cookieValue)
```

### After
```go
req.Header.Set(http.ContentType, http.ContentTypeJSON)
req.Header.Get(http.Authorization)
resp.Header.Add(http.SetCookie, cookieValue)
```

## Benefits

1. **Type Safety**: Constants prevent typos in header names
2. **IDE Support**: Autocomplete for all header names
3. **Consistency**: Standardized header names across the codebase
4. **Maintainability**: Easy to update header names globally
5. **Documentation**: Self-documenting code with clear header purposes

## Constants Reference

### Standard HTTP Headers
- `Accept`, `AcceptEncoding`, `AcceptLanguage`
- `Authorization`, `CacheControl`, `Connection`
- `ContentType`, `ContentEncoding`, `ContentLength`
- `Cookie`, `Host`, `Origin`, `Referer`, `UserAgent`
- `ETag`, `LastModified`, `SetCookie`, `Date`, `Expires`

### Proxy Headers
- `XForwardedFor`, `XForwardedHost`, `XForwardedProto`
- `XRealIP`, `XRequestID`

### SoapBucket Custom Headers
- `XSoapBucketTransformsApplied`

### Content Types
- `ContentTypeJSON`, `ContentTypeFormURLEncoded`
- `ContentTypeHTML`, `ContentTypeXML`, `ContentTypeText`

### Cache Control Values
- `CacheControlNoCache`, `CacheControlNoStore`
- `CacheControlPrivate`, `CacheControlPublic`

### User Agents
- `UserAgentSoapBucket`, `UserAgentMozilla`
- `UserAgentTest`, `UserAgentIntegration`, `UserAgentBenchmark`

---

## Security Validation (NEW)

The httputil package now includes comprehensive security validation to protect against common web vulnerabilities. This addresses critical security gaps identified in the security audit.

### Key Security Features

- **Input Validation**: Comprehensive validation of all request inputs
- **Injection Prevention**: SQL, XSS, LDAP, XML, and command injection detection
- **Path Traversal Protection**: Prevents directory traversal attacks
- **Header Injection Protection**: CRLF injection prevention
- **Size Limits**: Configurable limits to prevent DoS attacks
- **Security Headers**: Automatic security header generation
- **Pattern Detection**: Regex-based suspicious pattern detection

### Quick Start - Security Validation

```go
import "github.com/soapbucket/sbproxy/internal/httpkit/httputil"

// Validate an incoming HTTP request
result := httputil.ValidateRequest(req)

if !result.Valid {
    // Request failed validation
    for _, err := range result.Errors {
        log.Error("Validation error:", err)
    }
    http.Error(w, "Invalid request", http.StatusBadRequest)
    return
}

// Log warnings for suspicious patterns
for _, warning := range result.Warnings {
    log.Warn("Suspicious pattern detected:", warning)
}

// Continue processing valid request
```

### Individual Validation Functions

```go
// Validate URL
if err := httputil.ValidateURL(req.URL); err != nil {
    // Handle invalid URL
}

// Validate path for path traversal
if err := httputil.ValidatePath(req.URL.Path); err != nil {
    // Handle path traversal attempt
}

// Validate query parameters
if err := httputil.ValidateQueryParams(req.URL.Query()); err != nil {
    // Handle invalid query parameters
}

// Validate headers for injection attacks
if err := httputil.ValidateHeaders(req.Header); err != nil {
    // Handle header injection attempt
}

// Validate hostname
if err := httputil.ValidateHostname(req.Host); err != nil {
    // Handle invalid hostname
}
```

### Input Sanitization

```go
// Sanitize user input (removes control characters, null bytes, CRLF)
sanitized := httputil.SanitizeInput(userInput)

// Sanitize header value (removes CRLF, null bytes)
cleanHeader := httputil.SanitizeHeader(headerValue)
```

### Security Headers

```go
// Apply all recommended security headers to response
httputil.ApplySecurityHeaders(w)

// Or get headers as a map
headers := httputil.GetSecurityHeaders()
for key, value := range headers {
    w.Header().Set(key, value)
}
```

Applied headers include:
- `X-Frame-Options: DENY` - Prevents clickjacking
- `X-Content-Type-Options: nosniff` - Prevents MIME sniffing
- `X-XSS-Protection: 1; mode=block` - Enables XSS filter
- `Strict-Transport-Security` - Forces HTTPS
- `Content-Security-Policy` - Controls resource loading
- `Referrer-Policy` - Controls referrer information
- `Permissions-Policy` - Controls browser features

### Content Type Validation

```go
allowedTypes := []string{
    httputil.ContentTypeJSON,
    httputil.ContentTypeXML,
}

if err := httputil.ValidateContentType(req.Header.Get(httputil.HeaderContentType), allowedTypes); err != nil {
    // Content type not allowed
}
```

### Method and Origin Validation

```go
// Validate HTTP method
allowedMethods := []string{"GET", "POST", "PUT", "DELETE"}
if err := httputil.ValidateRequestMethod(req.Method, allowedMethods); err != nil {
    // Method not allowed
}

// Validate origin for CORS
allowedOrigins := []string{
    "https://example.com",
    "*.trusted.com",
}
if err := httputil.ValidateOrigin(req.Header.Get(httputil.HeaderOrigin), allowedOrigins); err != nil {
    // Origin not allowed
}
```

### Security Limits

The following limits are enforced to prevent DoS attacks:

| Limit | Value | Purpose |
|-------|-------|---------|
| `MaxURLLength` | 8192 bytes | Maximum URL length |
| `MaxHeaderSize` | 8192 bytes | Maximum header value size |
| `MaxHeaderCount` | 100 | Maximum number of headers |
| `MaxQueryParamLength` | 4096 bytes | Maximum query parameter length |
| `MaxQueryParamCount` | 100 | Maximum number of query params |
| `MaxPathLength` | 2048 bytes | Maximum path length |
| `MaxHostnameLength` | 253 bytes | Maximum hostname length |

### Detection Patterns

The security module detects the following attack patterns:

- **SQL Injection**: `UNION`, `SELECT`, `INSERT`, `UPDATE`, `DELETE`, etc.
- **XSS**: `<script>`, `javascript:`, `onerror=`, `onload=`, etc.
- **Path Traversal**: `../`, `..\`, encoded variants
- **LDAP Injection**: Special LDAP characters
- **XML Injection**: `<!ENTITY>`, `<!DOCTYPE>`, `<?xml>`
- **Command Injection**: `;`, `|`, `$`, backticks
- **Null Bytes**: `\x00`
- **CRLF Injection**: `\r\n`

### Security Validation Result

```go
type SecurityValidationResult struct {
    Valid              bool      // Overall validation status
    Errors             []error   // Validation errors (blocking)
    Warnings           []string  // Warnings (non-blocking)
    SuspiciousPatterns []string  // Detected suspicious patterns
}
```

### Helper Functions

```go
// Check if URL scheme is secure (HTTPS)
if httputil.IsSecureScheme(req.URL.Scheme) {
    // HTTPS connection
}

// Check if user agent is suspicious
if httputil.IsSuspiciousUserAgent(req.UserAgent()) {
    // Log suspicious user agent
}

// Generate rate limit key
key := httputil.RateLimitKey(clientIP, userID)

// Validate IP address format
if err := httputil.ValidateIPAddress(ip); err != nil {
    // Invalid IP address
}
```

### Best Practices

1. **Always Validate Input**: Call `ValidateRequest()` on all incoming requests
2. **Apply Security Headers**: Use `ApplySecurityHeaders()` on all responses
3. **Log Suspicious Activity**: Monitor `SuspiciousPatterns` and `Warnings`
4. **Sanitize When Necessary**: Use sanitization as a last resort; prefer validation + rejection
5. **Configure Limits**: Adjust security limits based on your application needs
6. **Review Patterns**: Regularly review and update detection patterns

### Performance

All regex patterns are pre-compiled at package initialization for optimal performance. Actual benchmarks (Apple M4 Max):

- `ValidateRequest()`: ~24.5 µs per request, 1820 B/op, 26 allocs/op
- `CheckSuspiciousPatterns()`: ~21.1 µs per request, 1650 B/op, 14 allocs/op
- `SanitizeInput()`: ~197 ns per string, 120 B/op, 4 allocs/op

These are highly optimized operations suitable for high-throughput production environments.

### Integration Example

```go
// Middleware for request validation
func SecurityValidationMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Apply security headers
        httputil.ApplySecurityHeaders(w)
        
        // Validate request
        result := httputil.ValidateRequest(r)
        
        if !result.Valid {
            log.Error("Request validation failed", "errors", result.Errors)
            http.Error(w, "Bad Request", http.StatusBadRequest)
            return
        }
        
        // Log suspicious patterns
        if len(result.SuspiciousPatterns) > 0 {
            log.Warn("Suspicious patterns detected",
                "patterns", result.SuspiciousPatterns,
                "ip", r.RemoteAddr,
                "path", r.URL.Path)
        }
        
        // Continue to next handler
        next.ServeHTTP(w, r)
    })
}
```

### Related Security Documentation

For more information on security best practices, see:
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

