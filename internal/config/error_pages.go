// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	templateresolver "github.com/soapbucket/sbproxy/internal/template"
)

const errorPageCacheType = "error_pages"

// errorContentType returns the default content type for error pages.
// Uses DefaultContentType if set, otherwise falls back to "text/html".
func (c *Config) errorContentType() string {
	if c.DefaultContentType != "" {
		return c.DefaultContentType
	}
	return "text/html"
}

// FindErrorPage finds the appropriate error page for a given status code
// Returns the error page and true if found, nil and false otherwise
// Priority: specific status codes first, then fallback to "all errors" page
func (ep ErrorPages) FindErrorPage(statusCode int) (*ErrorPage, bool) {
	// First, try to find a page that specifically matches this status code
	for i := range ep {
		if len(ep[i].Status) > 0 && slices.Contains(ep[i].Status, statusCode) {
			return &ep[i], true
		}
	}

	// If no specific match, look for a catch-all page (no status codes specified)
	for i := range ep {
		if len(ep[i].Status) == 0 {
			return &ep[i], true
		}
	}

	return nil, false
}

// ServeErrorPage serves a custom error page for the given status code
// Returns true if an error page was served, false otherwise
func (c *Config) ServeErrorPage(w http.ResponseWriter, r *http.Request, statusCode int, err error) bool {
	// Check if error pages are configured
	if len(c.ErrorPages) == 0 {
		// Check parent config if applicable
		if c.Parent != nil && !c.DisableApplyParent {
			return c.Parent.ServeErrorPage(w, r, statusCode, err)
		}
		return false
	}

	// Find matching error page
	errorPage, found := c.ErrorPages.FindErrorPage(statusCode)
	if !found {
		return false
	}

	slog.Debug("serving custom error page",
		"origin_id", c.ID,
		"status_code", statusCode)

	// If callback is configured, fetch the error page dynamically
	if errorPage.Callback != nil {
		return c.serveErrorPageFromCallback(w, r, statusCode, err, errorPage)
	}

	// Otherwise, serve static error page
	return c.serveStaticErrorPage(w, r, statusCode, err, errorPage)
}

// generateCallbackErrorPageCacheKey generates a cache key for a callback-based error page
func (c *Config) generateCallbackErrorPageCacheKey(errorPage *ErrorPage, statusCode int, callbackData map[string]any) string {
	// Build a unique key based on origin ID, status code, and callback data
	keyParts := []string{
		c.ID,
		fmt.Sprintf("status_%d", statusCode),
	}

	// Include callback URL and method in key
	if errorPage.Callback != nil {
		keyParts = append(keyParts, fmt.Sprintf("url_%s", errorPage.Callback.URL))
		keyParts = append(keyParts, fmt.Sprintf("method_%s", errorPage.Callback.Method))
	}

	// Include status codes in key if specified
	if len(errorPage.Status) > 0 {
		statusStr := ""
		for _, s := range errorPage.Status {
			statusStr += fmt.Sprintf("%d,", s)
		}
		keyParts = append(keyParts, fmt.Sprintf("codes_%s", statusStr))
	}

	// Include callback data hash for request-specific caching
	callbackDataJSON, _ := json.Marshal(callbackData)
	callbackHash := sha256.Sum256(callbackDataJSON)
	keyParts = append(keyParts, fmt.Sprintf("data_%x", callbackHash)[:16])

	// Include template flag (templates can't be cached as rendered, but we track them)
	if errorPage.Template {
		keyParts = append(keyParts, "template")
	}

	key := strings.Join(keyParts, ":")
	// Create SHA256 hash of the key for a fixed-length cache key
	hash := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", hash)
}

// serveErrorPageFromCallback fetches and serves an error page from a callback
func (c *Config) serveErrorPageFromCallback(w http.ResponseWriter, r *http.Request, statusCode int, err error, errorPage *ErrorPage) bool {
	ctx := r.Context()

	// Build request data for callback
	requestData := reqctx.GetRequestData(ctx)
	errorMsg := ""
	if err != nil {
		errorMsg = err.Error()
	}
	callbackData := map[string]any{
		"status_code": statusCode,
		"error":       errorMsg,
		"request": map[string]any{
			"url":    r.URL.String(),
			"method": r.Method,
		},
	}

	if requestData != nil {
		callbackData["context"] = requestData.Data
	}

	// For non-template callback pages, try to get from cache first
	if !errorPage.Template && c.l3Cache != nil && errorPage.Callback != nil && errorPage.Callback.CacheDuration.Duration > 0 {
		cacheKey := c.generateCallbackErrorPageCacheKey(errorPage, statusCode, callbackData)
		cachedReader, cacheErr := c.l3Cache.Get(ctx, errorPageCacheType, cacheKey)
		if cacheErr == nil && cachedReader != nil {
			// Cache hit - read and serve cached content
			cachedBody, readErr := io.ReadAll(cachedReader)
			if readErr == nil {
				slog.Debug("serving callback error page from L3 cache",
					"origin_id", c.ID,
					"status_code", statusCode,
					"cache_key", cacheKey)

				// Set headers from error page config
				if errorPage.Headers != nil {
					for key, value := range errorPage.Headers {
						w.Header().Set(key, value)
					}
				}

				// Determine content type
				contentType := errorPage.ContentType
				if contentType == "" {
					contentType = c.errorContentType()
				}
				w.Header().Set("Content-Type", contentType)

				// Determine status code
				responseStatusCode := statusCode
				if errorPage.StatusCode > 0 {
					responseStatusCode = errorPage.StatusCode
				}

				w.WriteHeader(responseStatusCode)
				w.Write(cachedBody)
				return true
			}
			slog.Warn("failed to read cached callback error page, falling back to system defaults",
				"origin_id", c.ID,
				"error", readErr)
			// If cache read fails, fall back to system defaults
			return false
		}
	}

	// Fetch error page content
	fetchResp, fetchErr := errorPage.Callback.Fetch(ctx, callbackData)
	if fetchErr != nil {
		slog.Error("failed to fetch error page from callback",
			"origin_id", c.ID,
			"status_code", statusCode,
			"error", fetchErr)
		return false
	}

	// Set headers from callback response (this includes Content-Type from callback)
	// But skip Content-Type if we need to override it after base64 decoding
	skipContentType := errorPage.DecodeBase64 && errorPage.ContentType != ""
	for key, values := range fetchResp.Headers {
		if skipContentType && strings.ToLower(key) == "content-type" {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Determine content type: prioritize callback's Content-Type, then error page's content_type, then default
	contentType := fetchResp.ContentType
	if contentType == "" {
		// Fall back to error page's content_type if callback didn't provide one
		if errorPage.ContentType != "" {
			contentType = errorPage.ContentType
		} else {
			contentType = c.errorContentType()
		}
	}
	// Override Content-Type if DecodeBase64 is true and ContentType is specified in error page config
	if errorPage.DecodeBase64 && errorPage.ContentType != "" {
		contentType = errorPage.ContentType
	}
	// Set Content-Type if it wasn't already set by the callback headers (or if we're overriding it)
	if w.Header().Get("Content-Type") == "" || (errorPage.DecodeBase64 && errorPage.ContentType != "") {
		w.Header().Set("Content-Type", contentType)
	}

	// Use status code from error page if specified, otherwise use the original status code
	responseStatusCode := statusCode
	if errorPage.StatusCode > 0 {
		responseStatusCode = errorPage.StatusCode
	}

	// Decode base64 if needed
	body := fetchResp.Body
	if errorPage.DecodeBase64 {
		decoded, decodeErr := base64.StdEncoding.DecodeString(string(fetchResp.Body))
		if decodeErr != nil {
			slog.Error("failed to decode base64 error page body from callback",
				"origin_id", c.ID,
				"error", decodeErr)
			// Fall back to original body if decoding fails
		} else {
			body = decoded
		}
	}

	// Render template if needed (after base64 decoding)
	if errorPage.Template {
		renderedBody, renderErr := c.renderErrorPageTemplate(string(body), r, statusCode, err)
		if renderErr != nil {
			slog.Error("failed to render error page template from callback, falling back to system defaults",
				"origin_id", c.ID,
				"error", renderErr)
			// If template rendering fails, fall back to system defaults
			return false
		}
		body = []byte(renderedBody)
	}

	// Cache callback-based error pages in L3 cache if callback has CacheDuration set
	// Note: Cache write errors are logged but don't fail the request
	if !errorPage.Template && c.l3Cache != nil && errorPage.Callback != nil && errorPage.Callback.CacheDuration.Duration > 0 {
		cacheKey := c.generateCallbackErrorPageCacheKey(errorPage, statusCode, callbackData)
		cacheDuration := errorPage.Callback.CacheDuration.Duration
		// Use PutWithExpires for time-limited caching
		if err := c.l3Cache.PutWithExpires(ctx, errorPageCacheType, cacheKey, bytes.NewReader(body), cacheDuration); err != nil {
			slog.Warn("failed to cache callback error page in L3 cache (non-fatal)",
				"origin_id", c.ID,
				"status_code", statusCode,
				"error", err)
			// Continue serving even if cache write fails
		} else {
			slog.Debug("cached callback error page in L3 cache",
				"origin_id", c.ID,
				"status_code", statusCode,
				"cache_key", cacheKey,
				"duration", cacheDuration)
		}
	}

	w.WriteHeader(responseStatusCode)
	w.Write(body)

	return true
}

// generateErrorPageCacheKey generates a cache key for an error page
func (c *Config) generateErrorPageCacheKey(errorPage *ErrorPage, statusCode int) string {
	// Build a unique key based on origin ID, status codes, and content hash
	// For templates, we include the template flag since they can't be cached
	keyParts := []string{
		c.ID,
		fmt.Sprintf("status_%d", statusCode),
	}

	// Include status codes in key if specified
	if len(errorPage.Status) > 0 {
		statusStr := ""
		for _, s := range errorPage.Status {
			statusStr += fmt.Sprintf("%d,", s)
		}
		keyParts = append(keyParts, fmt.Sprintf("codes_%s", statusStr))
	}

	// Include content hash to detect changes
	contentHash := c.getErrorPageContentHash(errorPage)
	keyParts = append(keyParts, fmt.Sprintf("hash_%s", contentHash))

	// Include template flag (templates can't be cached as rendered, but we track them)
	if errorPage.Template {
		keyParts = append(keyParts, "template")
	}

	key := strings.Join(keyParts, ":")
	// Create SHA256 hash of the key for a fixed-length cache key
	hash := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", hash)
}

// getErrorPageContentHash generates a hash of the error page content
func (c *Config) getErrorPageContentHash(errorPage *ErrorPage) string {
	var content string
	if errorPage.BodyBase64 != "" {
		content = errorPage.BodyBase64
	} else if errorPage.Body != "" {
		content = errorPage.Body
	} else if len(errorPage.JSONBody) > 0 {
		content = string(errorPage.JSONBody)
	}
	hash := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", hash)[:16] // Use first 16 chars for shorter key
}

// serveStaticErrorPage serves a static error page
func (c *Config) serveStaticErrorPage(w http.ResponseWriter, r *http.Request, statusCode int, err error, errorPage *ErrorPage) bool {
	ctx := r.Context()

	// Set headers
	if errorPage.Headers != nil {
		for key, value := range errorPage.Headers {
			w.Header().Set(key, value)
		}
	}

	// Determine content type
	contentType := errorPage.ContentType
	if contentType == "" {
		contentType = c.errorContentType()
	}
	w.Header().Set("Content-Type", contentType)

	// Determine status code
	responseStatusCode := statusCode
	if errorPage.StatusCode > 0 {
		responseStatusCode = errorPage.StatusCode
	}

	// Determine body content
	var body []byte
	var templateContent string
	var isTemplate bool

	if errorPage.BodyBase64 != "" {
		var decodeErr error
		body, decodeErr = base64.StdEncoding.DecodeString(errorPage.BodyBase64)
		if decodeErr != nil {
			slog.Error("failed to decode base64 error page body",
				"origin_id", c.ID,
				"error", decodeErr)
			return false
		}
		if errorPage.Template {
			templateContent = string(body)
			isTemplate = true
		}
	} else if errorPage.Body != "" {
		if errorPage.Template {
			templateContent = errorPage.Body
			isTemplate = true
		} else {
			body = []byte(errorPage.Body)
		}
	} else if len(errorPage.JSONBody) > 0 {
		if errorPage.Template {
			templateContent = string(errorPage.JSONBody)
			isTemplate = true
		} else {
			// Pretty print JSON if needed
			var jsonData interface{}
			if jsonErr := json.Unmarshal(errorPage.JSONBody, &jsonData); jsonErr == nil {
				body, _ = json.Marshal(jsonData)
				if contentType == "text/html" {
					contentType = "application/json"
					w.Header().Set("Content-Type", contentType)
				}
			} else {
				body = errorPage.JSONBody
			}
		}
	} else {
		// No body specified, use default error message
		body = []byte(http.StatusText(responseStatusCode))
	}

	// For non-template pages, try to get from cache
	if !isTemplate && c.l3Cache != nil {
		cacheKey := c.generateErrorPageCacheKey(errorPage, statusCode)
		cachedReader, err := c.l3Cache.Get(ctx, errorPageCacheType, cacheKey)
		if err == nil && cachedReader != nil {
			// Cache hit - read and serve cached content
			cachedBody, readErr := io.ReadAll(cachedReader)
			if readErr == nil {
				slog.Debug("serving error page from L3 cache",
					"origin_id", c.ID,
					"status_code", statusCode,
					"cache_key", cacheKey)
				w.WriteHeader(responseStatusCode)
				w.Write(cachedBody)
				return true
			}
			slog.Warn("failed to read cached error page, falling back to system defaults",
				"origin_id", c.ID,
				"error", readErr)
			// If cache read fails, fall back to system defaults
			return false
		}
	}

	// Render template if needed (templates are always rendered fresh, not cached)
	if isTemplate {
		renderedBody, renderErr := c.renderErrorPageTemplate(templateContent, r, statusCode, err)
		if renderErr != nil {
			slog.Error("failed to render error page template, falling back to system defaults",
				"origin_id", c.ID,
				"error", renderErr)
			// If template rendering fails, fall back to system defaults
			return false
		}
		body = []byte(renderedBody)
	}

	// Cache non-template static error pages in L3 cache (always indefinitely)
	// Note: Cache write errors are logged but don't fail the request
	if !isTemplate && c.l3Cache != nil {
		cacheKey := c.generateErrorPageCacheKey(errorPage, statusCode)
		// Static error pages are always cached indefinitely
		if err := c.l3Cache.Put(ctx, errorPageCacheType, cacheKey, bytes.NewReader(body)); err != nil {
			slog.Warn("failed to cache error page in L3 cache (non-fatal)",
				"origin_id", c.ID,
				"status_code", statusCode,
				"error", err)
			// Continue serving even if cache write fails
		} else {
			slog.Debug("cached static error page in L3 cache",
				"origin_id", c.ID,
				"status_code", statusCode,
				"cache_key", cacheKey,
				"duration", "indefinite")
		}
	}

	w.WriteHeader(responseStatusCode)
	w.Write(body)

	return true
}

// renderErrorPageTemplate renders an error page template with context data
func (c *Config) renderErrorPageTemplate(templateContent string, r *http.Request, statusCode int, err error) (string, error) {
	// Build template context
	requestData := reqctx.GetRequestData(r.Context())

	// Build headers map
	headers := make(map[string]string)
	for key, values := range r.Header {
		headers[strings.ToLower(key)] = strings.Join(values, ", ")
	}

	// Build request info
	requestInfo := map[string]any{
		"url":     r.URL.String(),
		"method":  r.Method,
		"path":    r.URL.Path,
		"query":   r.URL.RawQuery,
		"headers": headers,
	}

	// Build context data
	contextData := make(map[string]any)
	if requestData != nil && requestData.Data != nil {
		contextData = requestData.Data
	}

	// Build template context
	errorMsg := http.StatusText(statusCode)
	if err != nil {
		errorMsg = err.Error()
	}

	ctx := map[string]any{
		"status_code": statusCode,
		"error":       errorMsg,
		"request":     requestInfo,
		"context":     contextData,
		"origin_id":   c.ID,
		"hostname":    c.Hostname,
	}

	return templateresolver.ResolveWithContext(templateContent, ctx)
}
