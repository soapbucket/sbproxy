// Package httputil defines HTTP constants, header names, and shared request/response utilities.
package httputil

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// Security validation constants
const (
	// Maximum safe sizes to prevent DoS
	MaxURLLength = 8192 // 8KB for URL
	// MaxHeaderSize is the maximum allowed value for header size.
	MaxHeaderSize = 8192 // 8KB per header
	// MaxHeaderCount is the maximum allowed value for header count.
	MaxHeaderCount = 100 // Maximum number of headers
	// MaxQueryParamLength is the maximum allowed value for query param length.
	MaxQueryParamLength = 4096 // 4KB per query parameter
	// MaxQueryParamCount is the maximum allowed value for query param count.
	MaxQueryParamCount = 100 // Maximum number of query parameters
	// MaxPathLength is the maximum allowed value for path length.
	MaxPathLength = 2048 // 2KB for path
	// MaxHostnameLength is the maximum allowed value for hostname length.
	MaxHostnameLength = 253 // RFC 1035
	// MaxCookieSize is the maximum allowed value for cookie size.
	MaxCookieSize = 4096 // 4KB per cookie
	// MaxFormFieldSize is the maximum allowed value for form field size.
	MaxFormFieldSize = 10485760 // 10MB per form field

	// Security patterns
	PatternSQLInjection = `(?i)(union\s+(all\s+)?select|;\s*(drop|delete|update|insert|create|alter|exec)\b|'\s*(or|and)\s+|--\s|/\*.*\*/|xp_|0x[0-9a-f]{8,})`
	// PatternXSS is a constant for pattern xss.
	PatternXSS = `(?i)(<script|javascript:|onerror=|onload=|<iframe|eval\(|expression\()`
	// PatternPathTraversal is a constant for pattern path traversal.
	PatternPathTraversal = `\.\.(/|\\)`
	// PatternNullByte is a constant for pattern null byte.
	PatternNullByte = `\x00`
	// PatternCRLFInjection is a constant for pattern crlf injection.
	PatternCRLFInjection = `[\r\n]`
	// PatternLDAPInjection is a constant for pattern ldap injection.
	PatternLDAPInjection = `(\)\s*\(|\(&|\(\||!\()`
	// PatternXMLInjection is a constant for pattern xml injection.
	PatternXMLInjection = `(?i)(<!entity|<!doctype|<\?xml)`
	// PatternCommandInjection is a constant for pattern command injection.
	PatternCommandInjection = `[;&|$<>` + "`" + `]`
)

// Security error types
var (
	// ErrURLTooLong is a sentinel error for url too long conditions.
	ErrURLTooLong = fmt.Errorf("URL exceeds maximum length of %d bytes", MaxURLLength)
	// ErrHeaderTooLarge is a sentinel error for header too large conditions.
	ErrHeaderTooLarge = fmt.Errorf("header exceeds maximum size of %d bytes", MaxHeaderSize)
	// ErrTooManyHeaders is a sentinel error for too many headers conditions.
	ErrTooManyHeaders = fmt.Errorf("too many headers (max: %d)", MaxHeaderCount)
	// ErrTooManyQueryParams is a sentinel error for too many query params conditions.
	ErrTooManyQueryParams = fmt.Errorf("too many query parameters (max: %d)", MaxQueryParamCount)
	// ErrQueryParamTooLong is a sentinel error for query param too long conditions.
	ErrQueryParamTooLong = fmt.Errorf("query parameter exceeds maximum length of %d bytes", MaxQueryParamLength)
	// ErrPathTooLong is a sentinel error for path too long conditions.
	ErrPathTooLong = fmt.Errorf("path exceeds maximum length of %d bytes", MaxPathLength)
	// ErrInvalidUTF8 is a sentinel error for invalid utf8 conditions.
	ErrInvalidUTF8 = fmt.Errorf("invalid UTF-8 encoding detected")
	// ErrSQLInjection is a sentinel error for sql injection conditions.
	ErrSQLInjection = fmt.Errorf("potential SQL injection detected")
	// ErrXSSAttempt is a sentinel error for xss attempt conditions.
	ErrXSSAttempt = fmt.Errorf("potential XSS attempt detected")
	// ErrPathTraversal is a sentinel error for path traversal conditions.
	ErrPathTraversal = fmt.Errorf("path traversal attempt detected")
	// ErrNullByte is a sentinel error for null byte conditions.
	ErrNullByte = fmt.Errorf("null byte detected")
	// ErrHeaderInjection is a sentinel error for header injection conditions.
	ErrHeaderInjection = fmt.Errorf("header injection attempt detected (CRLF)")
	// ErrInvalidHostname is a sentinel error for invalid hostname conditions.
	ErrInvalidHostname = fmt.Errorf("invalid hostname")
	// ErrInvalidScheme is a sentinel error for invalid scheme conditions.
	ErrInvalidScheme = fmt.Errorf("invalid URL scheme")
	// ErrLDAPInjection is a sentinel error for ldap injection conditions.
	ErrLDAPInjection = fmt.Errorf("potential LDAP injection detected")
	// ErrXMLInjection is a sentinel error for xml injection conditions.
	ErrXMLInjection = fmt.Errorf("potential XML injection detected")
	// ErrCommandInjection is a sentinel error for command injection conditions.
	ErrCommandInjection = fmt.Errorf("potential command injection detected")
)

// Compiled regex patterns for performance (cached at package init)
var (
	sqlInjectionRegex     *regexp.Regexp
	xssRegex              *regexp.Regexp
	pathTraversalRegex    *regexp.Regexp
	nullByteRegex         *regexp.Regexp
	crlfInjectionRegex    *regexp.Regexp
	ldapInjectionRegex    *regexp.Regexp
	xmlInjectionRegex     *regexp.Regexp
	commandInjectionRegex *regexp.Regexp
)

func init() {
	// Pre-compile regex patterns for better performance
	sqlInjectionRegex = regexp.MustCompile(PatternSQLInjection)
	xssRegex = regexp.MustCompile(PatternXSS)
	pathTraversalRegex = regexp.MustCompile(PatternPathTraversal)
	nullByteRegex = regexp.MustCompile(PatternNullByte)
	crlfInjectionRegex = regexp.MustCompile(PatternCRLFInjection)
	ldapInjectionRegex = regexp.MustCompile(PatternLDAPInjection)
	xmlInjectionRegex = regexp.MustCompile(PatternXMLInjection)
	commandInjectionRegex = regexp.MustCompile(PatternCommandInjection)
}

// SecurityValidationResult contains the results of security validation
type SecurityValidationResult struct {
	Valid              bool
	Errors             []error
	Warnings           []string
	SuspiciousPatterns []string
}

// AddError adds an error to the validation result
func (r *SecurityValidationResult) AddError(err error) {
	r.Valid = false
	r.Errors = append(r.Errors, err)
}

// AddWarning adds a warning to the validation result
func (r *SecurityValidationResult) AddWarning(warning string) {
	r.Warnings = append(r.Warnings, warning)
}

// AddSuspiciousPattern adds a suspicious pattern to the validation result
func (r *SecurityValidationResult) AddSuspiciousPattern(pattern string) {
	r.SuspiciousPatterns = append(r.SuspiciousPatterns, pattern)
}

// ValidateRequest performs comprehensive security validation on an HTTP request
// This is the main entry point for request security validation
func ValidateRequest(r *http.Request) *SecurityValidationResult {
	return ValidateRequestWithOrigin(r, "")
}

// ValidateRequestWithOrigin performs comprehensive security validation on an HTTP request with origin tracking
func ValidateRequestWithOrigin(r *http.Request, origin string) *SecurityValidationResult {
	result := &SecurityValidationResult{Valid: true}

	// Validate URL
	if err := ValidateURL(r.URL); err != nil {
		result.AddError(err)
	}

	// Validate headers with origin tracking
	if err := ValidateHeadersWithOrigin(r.Header, origin); err != nil {
		result.AddError(err)
	}

	// Validate path
	// Note: Go's HTTP server normalizes paths (e.g., /../../../etc/passwd -> /etc/passwd)
	// So we check both the normalized path and the RequestURI() which may contain the original
	if err := ValidatePath(r.URL.Path); err != nil {
		result.AddError(err)
	}
	// Also check RequestURI() for path traversal before normalization
	// RequestURI() contains the original request line before Go normalizes it
	if r.URL.RequestURI() != "" && r.URL.RequestURI() != r.URL.Path {
		// Extract just the path portion (before query string)
		requestURI := r.URL.RequestURI()
		if idx := strings.Index(requestURI, "?"); idx > 0 {
			requestURI = requestURI[:idx]
		}
		// Check if RequestURI contains path traversal that was normalized in Path
		if err := ValidatePath(requestURI); err != nil {
			result.AddError(err)
		}
	}

	// Validate query parameters
	if err := ValidateQueryParams(r.URL.Query()); err != nil {
		result.AddError(err)
	}

	// Validate host
	if err := ValidateHostname(r.Host); err != nil {
		result.AddError(err)
	}

	// Check for suspicious patterns
	CheckSuspiciousPatterns(r, result)

	return result
}

// ValidateURL validates the entire URL for security issues
func ValidateURL(u *url.URL) error {
	if u == nil {
		return fmt.Errorf("URL is nil")
	}

	// Check URL length
	urlStr := u.String()
	if len(urlStr) > MaxURLLength {
		return ErrURLTooLong
	}

	// Validate UTF-8 encoding
	if !utf8.ValidString(urlStr) {
		return ErrInvalidUTF8
	}

	// Validate scheme
	if u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" {
		return ErrInvalidScheme
	}

	// Check for null bytes
	if nullByteRegex.MatchString(urlStr) {
		return ErrNullByte
	}

	return nil
}

// ValidatePath validates the URL path for path traversal and other attacks
func ValidatePath(path string) error {
	// Check path length
	if len(path) > MaxPathLength {
		return ErrPathTooLong
	}

	// Validate UTF-8 encoding
	if !utf8.ValidString(path) {
		return ErrInvalidUTF8
	}

	// Check for path traversal
	if pathTraversalRegex.MatchString(path) {
		return ErrPathTraversal
	}

	// Check for null bytes
	if nullByteRegex.MatchString(path) {
		return ErrNullByte
	}

	// Additional check for encoded path traversal attempts
	decoded, err := url.PathUnescape(path)
	if err == nil && pathTraversalRegex.MatchString(decoded) {
		return ErrPathTraversal
	}

	return nil
}

// ValidateQueryParams validates query parameters for injection attacks
func ValidateQueryParams(params url.Values) error {
	// Check number of parameters
	if len(params) > MaxQueryParamCount {
		return ErrTooManyQueryParams
	}

	// Validate each parameter
	for key, values := range params {
		// Check key length and encoding
		if len(key) > MaxQueryParamLength {
			return ErrQueryParamTooLong
		}

		if !utf8.ValidString(key) {
			return ErrInvalidUTF8
		}

		// Check for null bytes in key
		if nullByteRegex.MatchString(key) {
			return ErrNullByte
		}

		// Validate each value
		for _, value := range values {
			if len(value) > MaxQueryParamLength {
				return ErrQueryParamTooLong
			}

			if !utf8.ValidString(value) {
				return ErrInvalidUTF8
			}

			// Check for null bytes in value
			if nullByteRegex.MatchString(value) {
				return ErrNullByte
			}
		}
	}

	return nil
}

// ValidateHeaders validates HTTP headers for injection attacks
// origin parameter is used for metrics tracking (can be empty if not available)
func ValidateHeaders(headers http.Header) error {
	return ValidateHeadersWithOrigin(headers, "")
}

// ValidateHeadersWithOrigin validates HTTP headers for injection attacks with origin tracking
func ValidateHeadersWithOrigin(headers http.Header, origin string) error {
	if origin == "" {
		origin = "unknown"
	}

	// Check number of headers
	if len(headers) > MaxHeaderCount {
		metric.SecurityHeaderViolation(origin, "all", "too_many_headers")
		return ErrTooManyHeaders
	}

	// Validate each header
	for name, values := range headers {
		// Validate header name
		if !utf8.ValidString(name) {
			metric.SecurityHeaderViolation(origin, name, "invalid_utf8_name")
			return ErrInvalidUTF8
		}

		// Check for CRLF injection in header name
		if crlfInjectionRegex.MatchString(name) {
			metric.SecurityHeaderViolation(origin, name, "crlf_injection_name")
			return ErrHeaderInjection
		}

		// Validate each header value
		for _, value := range values {
			// Check header size
			if len(value) > MaxHeaderSize {
				metric.SecurityHeaderViolation(origin, name, "header_too_large")
				return ErrHeaderTooLarge
			}

			// Validate UTF-8 encoding
			if !utf8.ValidString(value) {
				metric.SecurityHeaderViolation(origin, name, "invalid_utf8_value")
				return ErrInvalidUTF8
			}

			// Check for CRLF injection in header value
			if crlfInjectionRegex.MatchString(value) {
				metric.SecurityHeaderViolation(origin, name, "crlf_injection_value")
				return ErrHeaderInjection
			}

			// Check for null bytes
			if nullByteRegex.MatchString(value) {
				metric.SecurityHeaderViolation(origin, name, "null_byte")
				return ErrNullByte
			}
		}
	}

	return nil
}

// ValidateHostname validates the hostname for security issues
func ValidateHostname(host string) error {
	if host == "" {
		return fmt.Errorf("hostname is empty")
	}

	// Check hostname length
	if len(host) > MaxHostnameLength {
		return ErrInvalidHostname
	}

	// Validate UTF-8 encoding
	if !utf8.ValidString(host) {
		return ErrInvalidUTF8
	}

	// Check for null bytes
	if nullByteRegex.MatchString(host) {
		return ErrNullByte
	}

	// Remove port if present
	hostname := host
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		hostname = host[:idx]
	}

	// Basic hostname validation (alphanumeric, dots, hyphens, colons for IPv6)
	// IPv6 addresses are enclosed in brackets
	for _, char := range hostname {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '.' || char == '-' || char == '[' || char == ']' || char == ':') {
			return ErrInvalidHostname
		}
	}

	return nil
}

// CheckSuspiciousPatterns checks for suspicious patterns that might indicate attacks
func CheckSuspiciousPatterns(r *http.Request, result *SecurityValidationResult) {
	// Combine all input sources for pattern checking
	inputs := []string{
		r.URL.String(),
		r.URL.Path,
		r.URL.RawQuery,
		r.Host,
		r.Referer(),
		r.UserAgent(),
	}

	// Add header values
	for _, values := range r.Header {
		inputs = append(inputs, values...)
	}

	// Add query parameter values
	for _, values := range r.URL.Query() {
		inputs = append(inputs, values...)
	}

	// Check each input for suspicious patterns
	for _, input := range inputs {
		if input == "" {
			continue
		}

		// Check for SQL injection patterns
		if sqlInjectionRegex.MatchString(input) {
			result.AddSuspiciousPattern("SQL injection pattern detected")
			result.AddWarning(fmt.Sprintf("Potential SQL injection in: %s", truncateString(input, 100)))
		}

		// Check for XSS patterns
		if xssRegex.MatchString(input) {
			result.AddSuspiciousPattern("XSS pattern detected")
			result.AddWarning(fmt.Sprintf("Potential XSS attempt in: %s", truncateString(input, 100)))
		}

		// Check for LDAP injection patterns
		if ldapInjectionRegex.MatchString(input) {
			result.AddSuspiciousPattern("LDAP injection pattern detected")
			result.AddWarning(fmt.Sprintf("Potential LDAP injection in: %s", truncateString(input, 100)))
		}

		// Check for XML injection patterns
		if xmlInjectionRegex.MatchString(input) {
			result.AddSuspiciousPattern("XML injection pattern detected")
			result.AddWarning(fmt.Sprintf("Potential XML injection in: %s", truncateString(input, 100)))
		}

		// Check for command injection patterns
		if commandInjectionRegex.MatchString(input) {
			result.AddSuspiciousPattern("Command injection pattern detected")
			result.AddWarning(fmt.Sprintf("Potential command injection in: %s", truncateString(input, 100)))
		}
	}
}

// SanitizeInput sanitizes user input by removing or escaping dangerous characters
// This is a basic sanitization - use with caution and prefer validation + rejection
func SanitizeInput(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")

	// Remove CRLF characters
	input = strings.ReplaceAll(input, "\r", "")
	input = strings.ReplaceAll(input, "\n", "")

	// Remove control characters (except tab, newline which we already handled)
	var sanitized strings.Builder
	for _, r := range input {
		if r >= 32 || r == '\t' {
			sanitized.WriteRune(r)
		}
	}

	return sanitized.String()
}

// SanitizeHeader sanitizes a header value for safe use
func SanitizeHeader(value string) string {
	// Remove CRLF to prevent header injection
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", "")

	// Remove null bytes
	value = strings.ReplaceAll(value, "\x00", "")

	return strings.TrimSpace(value)
}

// ValidateContentType validates that the Content-Type header matches expected values
func ValidateContentType(contentType string, allowedTypes []string) error {
	if contentType == "" {
		return nil // Allow empty content type
	}

	// Extract media type (ignore parameters like charset)
	mediaType := contentType
	if idx := strings.Index(contentType, ";"); idx > 0 {
		mediaType = strings.TrimSpace(contentType[:idx])
	}

	// Check against allowed types
	for _, allowed := range allowedTypes {
		if strings.EqualFold(mediaType, allowed) {
			return nil
		}
	}

	return fmt.Errorf("content type '%s' not in allowed list", mediaType)
}

// IsSecureScheme checks if the URL scheme is secure (https)
func IsSecureScheme(scheme string) bool {
	return strings.EqualFold(scheme, "https")
}

// GetSecurityHeaders returns a map of recommended security headers
// These headers should be added to responses to improve security
func GetSecurityHeaders() map[string]string {
	return map[string]string{
		// Prevent clickjacking
		"X-Frame-Options": "DENY",

		// Enable XSS protection
		"X-Content-Type-Options": "nosniff",

		// Enable XSS filter
		"X-XSS-Protection": "1; mode=block",

		// Strict Transport Security (HSTS) - 1 year
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",

		// Content Security Policy - adjust as needed
		"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'",

		// Referrer Policy
		"Referrer-Policy": "strict-origin-when-cross-origin",

		// Permissions Policy (formerly Feature-Policy)
		"Permissions-Policy": "geolocation=(), microphone=(), camera=()",
	}
}

// ApplySecurityHeaders applies security headers to an HTTP response
// It checks if headers are already set before applying to avoid overriding existing values
func ApplySecurityHeaders(w http.ResponseWriter) {
	headers := w.Header()
	for key, value := range GetSecurityHeaders() {
		// Special handling for Content-Security-Policy: check both regular and report-only variants
		if key == "Content-Security-Policy" {
			if headers.Get("Content-Security-Policy") == "" && headers.Get("Content-Security-Policy-Report-Only") == "" {
				headers.Set(key, value)
			}
			continue
		}

		// Check if header is already set before applying
		if headers.Get(key) == "" {
			headers.Set(key, value)
		}
	}
}

// truncateString truncates a string to maxLen characters for logging
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ValidateIPAddress validates an IP address format (IPv4 or IPv6)
func ValidateIPAddress(ip string) error {
	if ip == "" {
		return fmt.Errorf("IP address is empty")
	}

	// Check for null bytes
	if nullByteRegex.MatchString(ip) {
		return ErrNullByte
	}

	// Basic validation - more thorough validation should use net.ParseIP
	if !strings.Contains(ip, ".") && !strings.Contains(ip, ":") {
		return fmt.Errorf("invalid IP address format")
	}

	return nil
}

// IsSuspiciousUserAgent checks if a User-Agent string is suspicious
func IsSuspiciousUserAgent(userAgent string) bool {
	if userAgent == "" {
		return true // Empty user agent is suspicious
	}

	// List of suspicious patterns
	suspiciousPatterns := []string{
		"curl",
		"wget",
		"python-requests",
		"bot",
		"crawler",
		"spider",
		"scraper",
		"<script",
		"javascript:",
	}

	userAgentLower := strings.ToLower(userAgent)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(userAgentLower, pattern) {
			return true
		}
	}

	return false
}

// ValidateRequestMethod validates that the HTTP method is allowed
func ValidateRequestMethod(method string, allowedMethods []string) error {
	for _, allowed := range allowedMethods {
		if strings.EqualFold(method, allowed) {
			return nil
		}
	}

	return fmt.Errorf("HTTP method '%s' not allowed", method)
}

// ValidateOrigin validates the Origin header for CORS requests
func ValidateOrigin(origin string, allowedOrigins []string) error {
	if origin == "" {
		return nil // No origin header is acceptable for non-CORS requests
	}

	// Validate the origin URL
	u, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("invalid origin URL: %w", err)
	}

	// Validate origin against allowed list
	for _, allowed := range allowedOrigins {
		if allowed == "*" || strings.EqualFold(origin, allowed) {
			return nil
		}

		// Check for wildcard subdomain match (e.g., *.example.com)
		if strings.HasPrefix(allowed, "*.") {
			domain := allowed[2:]
			if strings.HasSuffix(u.Host, domain) {
				return nil
			}
		}
	}

	return fmt.Errorf("origin '%s' not allowed", origin)
}

// RateLimitKey generates a key for rate limiting based on IP and optional user ID
func RateLimitKey(ip string, userID string) string {
	if userID != "" {
		return fmt.Sprintf("ratelimit:user:%s", userID)
	}
	return fmt.Sprintf("ratelimit:ip:%s", ip)
}
