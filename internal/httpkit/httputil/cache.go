// Package httputil defines HTTP constants, header names, and shared request/response utilities.
package httputil

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// IsCacheable checks if an HTTP request is cacheable according to HTTP/1.1 spec
// RFC 7234 Section 4.2: Cacheable Methods
func IsCacheable(req *http.Request) bool {
	// Only GET and HEAD requests are cacheable by default
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return false
	}

	// Check for no-cache directive in request
	if req.Header.Get(HeaderCacheControl) != "" {
		cacheControl := strings.ToLower(req.Header.Get(HeaderCacheControl))
		if strings.Contains(cacheControl, "no-cache") || strings.Contains(cacheControl, "no-store") {
			return false
		}
	}

	// Check for authorization header (unless explicitly allowed)
	if req.Header.Get(HeaderAuthorization) != "" {
		// Authorization requests are typically not cacheable unless explicitly allowed
		// This could be made configurable
		return false
	}

	return true
}

// GenerateCacheKey creates a cache key from an HTTP request following HTTP/1.1 spec
// RFC 7234 Section 4.1: Constructing Responses from Caches
// Also accounts for load balancer sticky session cookies, workspace_id, and config_id
func GenerateCacheKey(req *http.Request) string {
	// Extract workspace_id and config_id from RequestData.Config
	if requestData := reqctx.GetRequestData(req.Context()); requestData != nil && requestData.Config != nil {
		configParams := reqctx.ConfigParams(requestData.Config)
		customValues := make(map[string]string, 2)
		if workspaceID := configParams.GetWorkspaceID(); workspaceID != "" {
			customValues["workspace_id"] = workspaceID
		}
		if configID := configParams.GetConfigID(); configID != "" {
			customValues["config_id"] = configID
		}
		if len(customValues) > 0 {
			return GenerateCacheKeyWithCustomValues(req, customValues)
		}
	}

	return GenerateCacheKeyWithCustomValues(req, nil)
}

// GenerateCacheKeyWithCustomValues creates a cache key from an HTTP request with custom values
// RFC 7234 Section 4.1: Constructing Responses from Caches
// Also accounts for load balancer sticky session cookies and custom cache values
func GenerateCacheKeyWithCustomValues(req *http.Request, customValues map[string]string) string {
	rawKey := generateRawCacheKeyWithCustomValues(req, customValues)
	// Create SHA256 hash of the key for consistent length
	hash := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(hash[:])
}

// generateRawCacheKey creates the raw cache key string before hashing
// This is used for testing and debugging
func generateRawCacheKey(req *http.Request) string {
	return generateRawCacheKeyWithCustomValues(req, nil)
}

// generateRawCacheKeyWithCustomValues creates the raw cache key string before hashing with custom values
// This is used for testing and debugging
func generateRawCacheKeyWithCustomValues(req *http.Request, customValues map[string]string) string {
	// Start with method and base URL (without query)
	baseURL := req.URL.Scheme + "://" + req.URL.Host + req.URL.Path
	key := req.Method + ":" + baseURL

	// Sort and normalize query parameters
	if req.URL.RawQuery != "" {
		query, err := url.ParseQuery(req.URL.RawQuery)
		if err == nil {
			// Remove empty values and sort
			var params []string
			for name, values := range query {
				if len(values) > 0 && values[0] != "" {
					// Sort values for consistency
					sort.Strings(values)
					params = append(params, name+"="+strings.Join(values, ","))
				}
			}
			sort.Strings(params)
			key += "?" + strings.Join(params, "&")
		}
	}

	// Add Vary headers to the key
	varyHeaders := req.Header.Get(HeaderVary)
	if varyHeaders != "" {
		// Parse vary headers and add them to the key
		varies := strings.Split(varyHeaders, ",")
		var varyValues []string
		for _, vary := range varies {
			vary = strings.TrimSpace(vary)
			if vary != "" {
				// Add the vary header value to the key (lowercase header name)
				value := req.Header.Get(vary)
				if value != "" {
					varyValues = append(varyValues, strings.ToLower(vary)+":"+value)
				}
			}
		}
		if len(varyValues) > 0 {
			sort.Strings(varyValues)
			key += "|vary:" + strings.Join(varyValues, ",")
		}
	}

	// Add custom cache values to the key
	if len(customValues) > 0 {
		var customPairs []string
		for k, v := range customValues {
			if k != "" && v != "" {
				customPairs = append(customPairs, k+":"+v)
			}
		}
		if len(customPairs) > 0 {
			sort.Strings(customPairs)
			key += "|custom:" + strings.Join(customPairs, ",")
		}
	}

	return key
}

// CalculateCacheDuration determines how long content can be cached based on response headers
// RFC 7234 Section 4.2: Cache-Control
func CalculateCacheDuration(resp *http.Response) *CachedResponse {
	cached := &CachedResponse{
		StatusCode:  resp.StatusCode,
		Headers:     make(map[string]string),
		VaryHeaders: []string{},
	}

	// Copy relevant headers
	for name, values := range resp.Header {
		if len(values) > 0 {
			cached.Headers[name] = values[0]
		}
	}

	// Parse Cache-Control header
	cacheControl := resp.Header.Get(HeaderCacheControl)
	if cacheControl != "" {
		directives := parseCacheControl(cacheControl)

		cached.MaxAge = directives["max-age"]
		cached.MustRevalidate = directives["must-revalidate"] > 0
		cached.NoCache = directives["no-cache"] > 0
		cached.NoStore = directives["no-store"] > 0
		cached.Private = directives["private"] > 0
		cached.Public = directives["public"] > 0
	}

	// Parse Vary header
	if vary := resp.Header.Get(HeaderVary); vary != "" {
		varies := strings.Split(vary, ",")
		for _, v := range varies {
			v = strings.TrimSpace(v)
			if v != "" {
				cached.VaryHeaders = append(cached.VaryHeaders, v)
			}
		}
	}

	// Parse ETag
	if etag := resp.Header.Get(HeaderETag); etag != "" {
		cached.ETag = etag
	}

	// Parse Last-Modified
	if lastMod := resp.Header.Get(HeaderLastModified); lastMod != "" {
		if t, err := time.Parse(time.RFC1123, lastMod); err == nil {
			cached.LastModified = t
		}
	}

	// Calculate expiration time
	now := time.Now()

	// Check for no-store directive
	if cached.NoStore {
		cached.Expires = now.Add(-time.Hour) // Never cache
		return cached
	}

	// Use max-age if available
	if cached.MaxAge > 0 {
		cached.Expires = now.Add(time.Duration(cached.MaxAge) * time.Second)
		cached.StaleDuration = time.Duration(cached.MaxAge) * time.Second
	} else {
		// Fall back to Expires header
		if expires := resp.Header.Get(HeaderExpires); expires != "" {
			if t, err := time.Parse(time.RFC1123, expires); err == nil {
				cached.Expires = t
				cached.StaleDuration = t.Sub(now)
			}
		} else {
			// Default to 1 hour if no expiration specified
			cached.Expires = now.Add(time.Hour)
			cached.StaleDuration = time.Hour
		}
	}

	// Add stale-while-revalidate if present
	if staleWhileRevalidate := parseStaleWhileRevalidate(cacheControl); staleWhileRevalidate > 0 {
		cached.StaleDuration += time.Duration(staleWhileRevalidate) * time.Second
	}

	return cached
}

// IsCacheValid checks if a cached response is still valid for a given request
// RFC 7234 Section 4.3: Storing Responses in Caches
func IsCacheValid(req *http.Request, cached *CachedResponse) (bool, bool) {
	now := time.Now()

	// Check if cache has expired
	if now.After(cached.Expires) {
		// Check if we can serve stale content
		staleExpiry := cached.Expires.Add(cached.StaleDuration)
		if now.After(staleExpiry) {
			return false, false // Cache is invalid and stale
		}
		// Cache is expired but within stale duration
		return false, true // Cache is stale but can be served
	}

	// Check conditional requests
	if req.Header.Get(HeaderIfNoneMatch) != "" {
		etag := req.Header.Get(HeaderIfNoneMatch)
		if etag == cached.ETag {
			return true, false // Cache is valid and fresh
		}
		return false, false // ETag mismatch
	}

	if req.Header.Get(HeaderIfModifiedSince) != "" {
		ifModifiedSince, err := time.Parse(time.RFC1123, req.Header.Get(HeaderIfModifiedSince))
		if err == nil {
			if cached.LastModified.After(ifModifiedSince) {
				return true, false // Cache is valid and fresh
			}
			return false, false // Content has been modified
		}
	}

	// Check if request has no-cache directive
	if req.Header.Get(HeaderCacheControl) != "" {
		cacheControl := strings.ToLower(req.Header.Get(HeaderCacheControl))
		if strings.Contains(cacheControl, "no-cache") {
			return false, false // Must revalidate
		}
	}

	// Check if cached response has must-revalidate
	if cached.MustRevalidate && now.After(cached.Expires) {
		return false, false // Must revalidate
	}

	return true, false // Cache is valid and fresh
}

// parseCacheControl parses Cache-Control header directives
func parseCacheControl(cacheControl string) map[string]int {
	directives := make(map[string]int)

	parts := strings.Split(strings.ToLower(cacheControl), ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)

		if strings.Contains(part, "=") {
			// Directive with value (e.g., max-age=3600)
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				if value, err := strconv.Atoi(kv[1]); err == nil {
					directives[kv[0]] = value
				}
			}
		} else {
			// Boolean directive (e.g., no-cache, no-store)
			directives[part] = 1
		}
	}

	return directives
}

// parseStaleWhileRevalidate extracts stale-while-revalidate value from Cache-Control
func parseStaleWhileRevalidate(cacheControl string) int {
	directives := parseCacheControl(cacheControl)
	return directives["stale-while-revalidate"]
}

// GetVaryHeaders extracts Vary headers from a response
func GetVaryHeaders(resp *http.Response) []string {
	vary := resp.Header.Get(HeaderVary)
	if vary == "" {
		return nil
	}

	var headers []string
	parts := strings.Split(vary, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			headers = append(headers, part)
		}
	}

	return headers
}

// ShouldVary checks if a request varies on the specified headers
func ShouldVary(req *http.Request, varyHeaders []string) bool {
	if len(varyHeaders) == 0 {
		return false
	}

	// Check if any of the vary headers are present in the request
	for _, vary := range varyHeaders {
		if req.Header.Get(vary) != "" {
			return true
		}
	}

	return false
}
