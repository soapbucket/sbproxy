// Package waf implements Web Application Firewall rules for request inspection and blocking.
package waf

import (
	"net/http"
	"net/url"
	"strings"
)

// ExtractVariables extracts values from HTTP request based on variable specifications
// Supports ModSecurity-style variables like ARGS, REQUEST_URI, REQUEST_HEADERS, etc.
func ExtractVariables(req *http.Request, variable WAFVariable) []string {
	var values []string

	name := strings.ToUpper(variable.Name)
	collection := strings.ToUpper(variable.Collection)

	// If collection is specified, use it; otherwise use name
	if collection != "" {
		name = collection
	}

	switch name {
	case "ARGS", "ARGS_NAMES", "ARGS_GET", "ARGS_POST":
		values = extractArgs(req, variable.Key)
	case "REQUEST_URI", "REQUEST_FILENAME", "REQUEST_BASENAME":
		values = extractRequestURI(req)
	case "REQUEST_METHOD":
		values = []string{req.Method}
	case "REQUEST_HEADERS", "REQUEST_HEADERS_NAMES":
		values = extractHeaders(req, variable.Key)
	case "QUERY_STRING":
		values = []string{req.URL.RawQuery}
	case "REQUEST_BODY":
		values = extractRequestBody(req)
	case "REQUEST_COOKIES", "REQUEST_COOKIES_NAMES":
		values = extractCookies(req, variable.Key)
	case "REMOTE_ADDR", "CLIENT_IP":
		values = extractRemoteAddr(req)
	case "REMOTE_HOST":
		values = extractRemoteHost(req)
	case "SERVER_NAME", "HTTP_HOST":
		values = []string{req.Host}
	case "REQUEST_PROTOCOL":
		values = []string{req.Proto}
	case "REQUEST_LINE":
		values = []string{req.Method + " " + req.URL.RequestURI() + " " + req.Proto}
	case "FILES", "FILES_NAMES":
		values = extractFiles(req, variable.Key)
	case "XML", "XML:/*":
		values = extractXML(req)
	case "JSON":
		values = extractJSON(req)
	default:
		// Try to match as a specific header
		if strings.HasPrefix(name, "REQUEST_HEADERS:") {
			headerName := strings.TrimPrefix(name, "REQUEST_HEADERS:")
			values = extractHeaders(req, headerName)
		} else if strings.HasPrefix(name, "ARGS:") {
			argName := strings.TrimPrefix(name, "ARGS:")
			values = extractArgs(req, argName)
		} else if strings.HasPrefix(name, "REQUEST_COOKIES:") {
			cookieName := strings.TrimPrefix(name, "REQUEST_COOKIES:")
			values = extractCookies(req, cookieName)
		}
	}

	// Apply transformations
	if len(variable.Transformations) > 0 {
		transformed := make([]string, len(values))
		for i, val := range values {
			transformed[i] = ApplyTransformations(val, variable.Transformations)
		}
		return transformed
	}

	return values
}

// extractArgs extracts query parameters and form values
func extractArgs(req *http.Request, key string) []string {
	var values []string

	// Extract from query string
	if key == "" {
		// Get all query values
		for _, vals := range req.URL.Query() {
			values = append(values, vals...)
		}
	} else {
		// Get specific query parameter
		if vals, ok := req.URL.Query()[key]; ok {
			values = append(values, vals...)
		}
	}

	// Extract from form data
	if req.Method == "POST" || req.Method == "PUT" || req.Method == "PATCH" {
		if err := req.ParseForm(); err == nil {
			if key == "" {
				// Get all form values
				for _, vals := range req.PostForm {
					values = append(values, vals...)
				}
			} else {
				// Get specific form field
				if vals, ok := req.PostForm[key]; ok {
					values = append(values, vals...)
				}
			}
		}
	}

	return values
}

// extractRequestURI extracts URI-related values
// Note: Go's HTTP server normalizes paths (e.g., /../../../etc/passwd -> /etc/passwd)
// We check multiple sources to catch path traversal attacks:
// 1. RawPath - original unnormalized path (if available, contains encoded characters)
// 2. RequestURI() - full request URI including query (may contain original path)
// 3. Path - normalized path (already processed by Go)
// 4. RawQuery - query string (may contain path traversal in parameters)
func extractRequestURI(req *http.Request) []string {
	values := []string{}

	// Prefer RawPath if available (contains original unnormalized path with encoded characters)
	// RawPath is set when the path contains characters that need encoding
	if req.URL.RawPath != "" {
		values = append(values, req.URL.RawPath)
		// Also decode it to check for patterns
		if decoded, err := url.PathUnescape(req.URL.RawPath); err == nil {
			values = append(values, decoded)
		}
	}

	// Check RequestURI() which includes the full request line (path + query)
	// This is the raw request URI before any normalization
	requestURI := req.URL.RequestURI()
	values = append(values, requestURI)

	// Also check just the path portion of RequestURI (before query)
	if idx := strings.Index(requestURI, "?"); idx > 0 {
		pathPart := requestURI[:idx]
		values = append(values, pathPart)
		// Try to decode it
		if decoded, err := url.PathUnescape(pathPart); err == nil {
			values = append(values, decoded)
		}
	} else {
		// No query, entire RequestURI is the path
		if decoded, err := url.PathUnescape(requestURI); err == nil {
			values = append(values, decoded)
		}
	}

	// Also check the normalized path (in case attack is in normalized form)
	// This won't catch ../ but might catch other patterns
	values = append(values, req.URL.Path)

	// Check RawQuery for path traversal in query parameters
	if req.URL.RawQuery != "" {
		values = append(values, req.URL.RawQuery)
	}

	return values
}

// extractHeaders extracts header values
func extractHeaders(req *http.Request, key string) []string {
	if key == "" {
		// Get all header values
		var values []string
		for _, vals := range req.Header {
			values = append(values, vals...)
		}
		return values
	}

	// Get specific header
	if vals, ok := req.Header[key]; ok {
		return vals
	}

	// Try case-insensitive match
	keyLower := strings.ToLower(key)
	for name, vals := range req.Header {
		if strings.ToLower(name) == keyLower {
			return vals
		}
	}

	return nil
}

// extractRequestBody extracts request body content
func extractRequestBody(req *http.Request) []string {
	// Note: This requires body to be read, which may have side effects
	// In production, body should be cached/peeked
	if req.Body != nil {
		// For now, return empty - body reading should be handled carefully
		// to avoid consuming the body stream
		return nil
	}
	return nil
}

// extractCookies extracts cookie values
func extractCookies(req *http.Request, key string) []string {
	if key == "" {
		// Get all cookie values
		var values []string
		for _, cookie := range req.Cookies() {
			values = append(values, cookie.Value)
		}
		return values
	}

	// Get specific cookie
	if cookie, err := req.Cookie(key); err == nil {
		return []string{cookie.Value}
	}

	return nil
}

// extractRemoteAddr extracts client IP address
func extractRemoteAddr(req *http.Request) []string {
	// Check X-Forwarded-For
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return []string{strings.TrimSpace(ips[0])}
		}
	}

	// Check X-Real-IP
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		return []string{xri}
	}

	// Use RemoteAddr
	if req.RemoteAddr != "" {
		// Remove port if present
		host, _, _ := strings.Cut(req.RemoteAddr, ":")
		return []string{host}
	}

	return nil
}

// extractRemoteHost extracts remote hostname
func extractRemoteHost(req *http.Request) []string {
	// Similar to remote addr, but would require reverse DNS lookup
	// For now, return the IP address
	return extractRemoteAddr(req)
}

// extractFiles extracts uploaded file information
func extractFiles(req *http.Request, key string) []string {
	// Parse multipart form
	if err := req.ParseMultipartForm(32 << 20); err == nil {
		if key == "" {
			// Get all file names
			var names []string
			for _, files := range req.MultipartForm.File {
				for _, file := range files {
					names = append(names, file.Filename)
				}
			}
			return names
		}

		// Get specific file field
		if files, ok := req.MultipartForm.File[key]; ok {
			var names []string
			for _, file := range files {
				names = append(names, file.Filename)
			}
			return names
		}
	}

	return nil
}

// extractXML extracts XML content from request
func extractXML(req *http.Request) []string {
	// Check Content-Type
	contentType := req.Header.Get("Content-Type")
	if strings.Contains(contentType, "xml") {
		// Would need to parse and extract XML content
		// For now, return empty
		return nil
	}
	return nil
}

// extractJSON extracts JSON content from request
func extractJSON(req *http.Request) []string {
	// Check Content-Type
	contentType := req.Header.Get("Content-Type")
	if strings.Contains(contentType, "json") {
		// Would need to parse and extract JSON content
		// For now, return empty
		return nil
	}
	return nil
}

// CombineValues combines multiple variable values into a single string for pattern matching
func CombineValues(values []string) string {
	return strings.Join(values, " ")
}
