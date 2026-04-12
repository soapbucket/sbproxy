// Package middleware contains HTTP middleware for authentication, rate limiting, logging, and request processing.
package middleware

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// ValidationConfig holds configuration for input validation middleware
type ValidationConfig struct {
	// Enabled controls whether validation is active
	Enabled bool

	// StrictMode causes validation failures to reject requests
	// If false, only logs warnings
	StrictMode bool

	// MaxRequestBodySize limits the size of request bodies (in bytes)
	// Default: 10MB
	MaxRequestBodySize int64

	// RequireContentTypeForBody requires Content-Type header for requests with bodies
	RequireContentTypeForBody bool

	// AllowedContentTypes lists acceptable Content-Type values (empty = allow all)
	AllowedContentTypes []string

	// ValidateSuspiciousPatterns enables checking for injection patterns
	ValidateSuspiciousPatterns bool

	// RejectSuspiciousPatterns causes requests with suspicious patterns to be rejected
	RejectSuspiciousPatterns bool
}

// DefaultValidationConfig returns a sensible default configuration
func DefaultValidationConfig() *ValidationConfig {
	return &ValidationConfig{
		Enabled:                    true,
		StrictMode:                 true,
		MaxRequestBodySize:         10 * 1024 * 1024, // 10MB
		RequireContentTypeForBody:  true,
		AllowedContentTypes:        []string{}, // Empty = allow all
		ValidateSuspiciousPatterns: true,
		RejectSuspiciousPatterns:   false, // Log only by default
	}
}

// ValidationMiddleware creates a middleware that performs comprehensive input validation
func ValidationMiddleware(config *ValidationConfig) func(http.Handler) http.Handler {
	if config == nil {
		config = DefaultValidationConfig()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip validation if disabled
			if !config.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Get config ID for metrics
			configID := "unknown"
			if requestData := reqctx.GetRequestData(r.Context()); requestData != nil && requestData.Config != nil {
				configData := reqctx.ConfigParams(requestData.Config)
				if id := configData.GetConfigID(); id != "" {
					configID = id
				}
			}
			
			// Perform comprehensive security validation with config ID tracking
			validationResult := httputil.ValidateRequestWithOrigin(r, configID)

			// Log validation results and record metrics
			if len(validationResult.Errors) > 0 {
				for _, err := range validationResult.Errors {
					slog.Warn("Request validation error",
						"error", err,
						"path", r.URL.Path,
						"method", r.Method,
						"remote_addr", r.RemoteAddr,
					)
					
					// Record input validation failure metric
					validationType := "unknown"
					fieldName := ""
					errStr := err.Error()
					
					// Determine validation type from error
					if strings.Contains(errStr, "path") || strings.Contains(errStr, "traversal") {
						validationType = "path_traversal"
						fieldName = "path"
					} else if strings.Contains(errStr, "header") || strings.Contains(errStr, "injection") {
						validationType = "header_injection"
						fieldName = "header"
					} else if strings.Contains(errStr, "query") {
						validationType = "query_injection"
						fieldName = "query"
					} else if strings.Contains(errStr, "null") {
						validationType = "null_byte"
						fieldName = "input"
					} else if strings.Contains(errStr, "UTF-8") {
						validationType = "encoding"
						fieldName = "input"
					} else if strings.Contains(errStr, "length") || strings.Contains(errStr, "too long") {
						validationType = "size_limit"
						fieldName = "input"
					}
					
					metric.InputValidationFailure(configID, validationType, fieldName)
				}

				// In strict mode, reject invalid requests
				if config.StrictMode {
					// Path traversal is an invalid request parameter, return 400 (Bad Request)
					statusCode := http.StatusBadRequest
					
					httputil.HandleError(
						statusCode,
						fmt.Errorf("request validation failed: %v", validationResult.Errors[0]),
						w,
						r,
					)
					return
				}
			}

			// Log warnings for suspicious patterns
			if len(validationResult.Warnings) > 0 {
				for _, warning := range validationResult.Warnings {
					slog.Warn("Suspicious pattern detected",
						"warning", warning,
						"path", r.URL.Path,
						"method", r.Method,
						"remote_addr", r.RemoteAddr,
					)
				}

				// Optionally reject requests with suspicious patterns
				if config.RejectSuspiciousPatterns {
					httputil.HandleError(
						http.StatusBadRequest,
						fmt.Errorf("suspicious pattern detected in request"),
						w,
						r,
					)
					return
				}
			}

			// Log suspicious patterns
			if len(validationResult.SuspiciousPatterns) > 0 && config.ValidateSuspiciousPatterns {
				requestData := reqctx.GetRequestData(r.Context())
				if requestData != nil {
					for _, pattern := range validationResult.SuspiciousPatterns {
						requestData.AddDebugHeader("X-Sb-Security-Warning", pattern)
					}
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequestSizeLimitConfig holds configuration for request size limiting
type RequestSizeLimitConfig struct {
	// Enabled controls whether size limiting is active
	Enabled bool

	// MaxBodySize is the maximum request body size in bytes
	// Default: 10MB
	MaxBodySize int64

	// PerRouteLimit allows custom limits per path pattern
	// Map of path prefix -> max size in bytes
	PerRouteLimit map[string]int64
}

// DefaultRequestSizeLimitConfig returns a sensible default configuration
func DefaultRequestSizeLimitConfig() *RequestSizeLimitConfig {
	return &RequestSizeLimitConfig{
		Enabled:       true,
		MaxBodySize:   10 * 1024 * 1024, // 10MB
		PerRouteLimit: make(map[string]int64),
	}
}

// RequestSizeLimitMiddleware creates middleware that enforces request body size limits
func RequestSizeLimitMiddleware(config *RequestSizeLimitConfig) func(http.Handler) http.Handler {
	if config == nil {
		config = DefaultRequestSizeLimitConfig()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip if disabled
			if !config.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Determine the max body size for this route
			maxSize := config.MaxBodySize

			// Check for per-route limits
			for pathPrefix, limit := range config.PerRouteLimit {
				if strings.HasPrefix(r.URL.Path, pathPrefix) {
					maxSize = limit
					break
				}
			}

			// Only limit methods that can have bodies
			if r.Method == http.MethodPost || r.Method == http.MethodPut ||
				r.Method == http.MethodPatch || r.Method == http.MethodDelete {

				// Check Content-Length header if present
				if r.ContentLength > maxSize {
					slog.Warn("Request body too large",
						"content_length", r.ContentLength,
						"max_size", maxSize,
						"path", r.URL.Path,
						"method", r.Method,
						"remote_addr", r.RemoteAddr,
					)

					http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
					return
				}

				// Wrap the body with a size-limiting reader
				r.Body = http.MaxBytesReader(w, r.Body, maxSize)

				// Store original context with size limit info
				ctx := context.WithValue(r.Context(), reqctx.ContextKeyMaxBodySize, maxSize)
				r = r.WithContext(ctx)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ContentTypeValidationConfig holds configuration for Content-Type validation
type ContentTypeValidationConfig struct {
	// Enabled controls whether validation is active
	Enabled bool

	// RequireContentType requires Content-Type header for requests with bodies
	RequireContentType bool

	// AllowedContentTypes lists acceptable Content-Type values
	// Empty list means all content types are allowed
	AllowedContentTypes []string

	// StrictMode rejects requests with invalid Content-Type
	// If false, only logs warnings
	StrictMode bool

	// PerRouteRules allows custom Content-Type rules per path pattern
	// Map of path prefix -> allowed content types
	PerRouteRules map[string][]string
}

// DefaultContentTypeValidationConfig returns a sensible default configuration
func DefaultContentTypeValidationConfig() *ContentTypeValidationConfig {
	return &ContentTypeValidationConfig{
		Enabled:            true,
		RequireContentType: true,
		AllowedContentTypes: []string{
			"application/json",
			"application/x-www-form-urlencoded",
			"multipart/form-data",
			"text/plain",
			"application/xml",
			"text/xml",
		},
		StrictMode:    false, // Start with warnings only
		PerRouteRules: make(map[string][]string),
	}
}

// ContentTypeValidationMiddleware creates middleware that validates Content-Type headers
func ContentTypeValidationMiddleware(config *ContentTypeValidationConfig) func(http.Handler) http.Handler {
	if config == nil {
		config = DefaultContentTypeValidationConfig()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip if disabled
			if !config.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Only validate methods that typically have bodies
			if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {

				contentType := r.Header.Get("Content-Type")

				// Check if Content-Type is required but missing
				if config.RequireContentType && contentType == "" && r.ContentLength > 0 {
					slog.Warn("Missing Content-Type header for request with body",
						"path", r.URL.Path,
						"method", r.Method,
						"content_length", r.ContentLength,
						"remote_addr", r.RemoteAddr,
					)

					if config.StrictMode {
						http.Error(w, "Content-Type header required", http.StatusBadRequest)
						return
					}
				}

				// Determine allowed content types for this route
				allowedTypes := config.AllowedContentTypes

				// Check for per-route rules
				for pathPrefix, types := range config.PerRouteRules {
					if strings.HasPrefix(r.URL.Path, pathPrefix) {
						allowedTypes = types
						break
					}
				}

				// Validate Content-Type if we have a list and a content type
				if len(allowedTypes) > 0 && contentType != "" {
					err := httputil.ValidateContentType(contentType, allowedTypes)
					if err != nil {
						slog.Warn("Invalid Content-Type header",
							"error", err,
							"content_type", contentType,
							"path", r.URL.Path,
							"method", r.Method,
							"remote_addr", r.RemoteAddr,
						)

						if config.StrictMode {
							http.Error(w, fmt.Sprintf("Invalid Content-Type: %v", err), http.StatusUnsupportedMediaType)
							return
						}
					}
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeadersConfig holds configuration for security headers
type SecurityHeadersConfig struct {
	// Enabled controls whether security headers are applied
	Enabled bool

	// CustomHeaders allows overriding default security headers
	CustomHeaders map[string]string

	// DisableHeaders lists headers that should not be set
	DisableHeaders []string
}

// DefaultSecurityHeadersConfig returns a sensible default configuration
func DefaultSecurityHeadersConfig() *SecurityHeadersConfig {
	return &SecurityHeadersConfig{
		Enabled:        true,
		CustomHeaders:  make(map[string]string),
		DisableHeaders: []string{},
	}
}

// SecurityHeadersMiddleware creates middleware that applies security headers to all responses
func SecurityHeadersMiddleware(config *SecurityHeadersConfig) func(http.Handler) http.Handler {
	if config == nil {
		config = DefaultSecurityHeadersConfig()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip if disabled
			if !config.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Get default security headers
			headers := httputil.GetSecurityHeaders()

			// Apply custom headers (overrides defaults)
			for key, value := range config.CustomHeaders {
				headers[key] = value
			}

			// Remove disabled headers
			for _, headerName := range config.DisableHeaders {
				delete(headers, headerName)
			}

			// Apply headers to response, but only if they don't already exist
			// This respects headers set by upstream responses or other middleware
			responseHeaders := w.Header()
			for key, value := range headers {
				// Special handling for Content-Security-Policy: check both regular and report-only variants
				if key == "Content-Security-Policy" {
					if responseHeaders.Get("Content-Security-Policy") == "" && responseHeaders.Get("Content-Security-Policy-Report-Only") == "" {
						responseHeaders.Set(key, value)
					}
					continue
				}
				
				// Check if header already exists using http.Header.Get() for proper canonicalization
				if responseHeaders.Get(key) == "" {
					responseHeaders.Set(key, value)
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// SizeLimitedReader wraps an io.ReadCloser with size limiting
type SizeLimitedReader struct {
	reader    io.ReadCloser
	remaining int64
	maxSize   int64
}

// NewSizeLimitedReader creates a new size-limited reader
func NewSizeLimitedReader(r io.ReadCloser, maxSize int64) *SizeLimitedReader {
	return &SizeLimitedReader{
		reader:    r,
		remaining: maxSize,
		maxSize:   maxSize,
	}
}

// Read implements io.Reader with size limiting
func (s *SizeLimitedReader) Read(p []byte) (n int, err error) {
	if s.remaining < 0 {
		return 0, fmt.Errorf("request body exceeds maximum size of %d bytes", s.maxSize)
	}

	if s.remaining == 0 {
		// We've read exactly the limit, check if there's more data
		// Try to read one byte to see if we've exceeded
		testBuf := make([]byte, 1)
		n, err := s.reader.Read(testBuf)
		if n > 0 {
			// There's more data, we've exceeded the limit
			return 0, fmt.Errorf("request body exceeds maximum size of %d bytes", s.maxSize)
		}
		// No more data, return EOF
		return 0, err
	}

	if int64(len(p)) > s.remaining {
		p = p[:s.remaining]
	}

	n, err = s.reader.Read(p)
	s.remaining -= int64(n)

	return n, err
}

// Close implements io.Closer
func (s *SizeLimitedReader) Close() error {
	return s.reader.Close()
}

