package httputil

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
		errType error
	}{
		{
			name:    "valid http URL",
			url:     "http://example.com/path",
			wantErr: false,
		},
		{
			name:    "valid https URL",
			url:     "https://example.com/path?query=value",
			wantErr: false,
		},
		{
			name:    "URL too long",
			url:     "http://example.com/" + strings.Repeat("a", MaxURLLength),
			wantErr: true,
			errType: ErrURLTooLong,
		},
		{
			name:    "URL with suspicious pattern",
			url:     "http://example.com/path",
			wantErr: false,
		},
		{
			name:    "invalid scheme",
			url:     "ftp://example.com/file",
			wantErr: true,
			errType: ErrInvalidScheme,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse(tt.url)
			err := ValidateURL(u)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateURL() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.errType != nil && err != tt.errType {
				t.Errorf("ValidateURL() error = %v, want %v", err, tt.errType)
			}
		})
	}
}

func TestValidatePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
		errType error
	}{
		{
			name:    "valid path",
			path:    "/api/v1/users",
			wantErr: false,
		},
		{
			name:    "path traversal attempt",
			path:    "/api/../../../etc/passwd",
			wantErr: true,
			errType: ErrPathTraversal,
		},
		{
			name:    "path traversal with backslash",
			path:    "/api/..\\..\\windows\\system32",
			wantErr: true,
			errType: ErrPathTraversal,
		},
		{
			name:    "encoded path traversal",
			path:    "/api/%2e%2e%2f%2e%2e%2fetc/passwd",
			wantErr: true,
			errType: ErrPathTraversal,
		},
		{
			name:    "null byte in path",
			path:    "/api/users\x00.txt",
			wantErr: true,
			errType: ErrNullByte,
		},
		{
			name:    "path too long",
			path:    "/" + strings.Repeat("a", MaxPathLength),
			wantErr: true,
			errType: ErrPathTooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePath() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.errType != nil && err != tt.errType {
				t.Errorf("ValidatePath() error = %v, want %v", err, tt.errType)
			}
		})
	}
}

func TestValidateQueryParams(t *testing.T) {
	tests := []struct {
		name    string
		params  url.Values
		wantErr bool
		errType error
	}{
		{
			name: "valid query params",
			params: url.Values{
				"name": []string{"John"},
				"age":  []string{"30"},
			},
			wantErr: false,
		},
		{
			name: "too many query params",
			params: func() url.Values {
				v := url.Values{}
				for i := 0; i < MaxQueryParamCount+1; i++ {
					v.Add(string(rune('a'+i)), "value")
				}
				return v
			}(),
			wantErr: true,
			errType: ErrTooManyQueryParams,
		},
		{
			name: "query param too long",
			params: url.Values{
				"data": []string{strings.Repeat("a", MaxQueryParamLength+1)},
			},
			wantErr: true,
			errType: ErrQueryParamTooLong,
		},
		{
			name: "null byte in query param",
			params: url.Values{
				"name": []string{"John\x00Doe"},
			},
			wantErr: true,
			errType: ErrNullByte,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateQueryParams(tt.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateQueryParams() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.errType != nil && err != tt.errType {
				t.Errorf("ValidateQueryParams() error = %v, want %v", err, tt.errType)
			}
		})
	}
}

func TestValidateHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		wantErr bool
		errType error
	}{
		{
			name: "valid headers",
			headers: http.Header{
				"Content-Type": []string{"application/json"},
				"User-Agent":   []string{"Mozilla/5.0"},
			},
			wantErr: false,
		},
		{
			name: "CRLF injection in header value",
			headers: http.Header{
				"X-Custom": []string{"value\r\nInjected-Header: malicious"},
			},
			wantErr: true,
			errType: ErrHeaderInjection,
		},
		{
			name: "CRLF injection in header name",
			headers: http.Header{
				"X-Custom\r\nInjected": []string{"value"},
			},
			wantErr: true,
			errType: ErrHeaderInjection,
		},
		{
			name: "header value too large",
			headers: http.Header{
				"X-Large": []string{strings.Repeat("a", MaxHeaderSize+1)},
			},
			wantErr: true,
			errType: ErrHeaderTooLarge,
		},
		{
			name: "null byte in header",
			headers: http.Header{
				"X-Custom": []string{"value\x00malicious"},
			},
			wantErr: true,
			errType: ErrNullByte,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHeaders(tt.headers)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHeaders() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.errType != nil && err != tt.errType {
				t.Errorf("ValidateHeaders() error = %v, want %v", err, tt.errType)
			}
		})
	}
}

func TestValidateHostname(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantErr bool
	}{
		{
			name:    "valid hostname",
			host:    "example.com",
			wantErr: false,
		},
		{
			name:    "valid hostname with port",
			host:    "example.com:8080",
			wantErr: false,
		},
		{
			name:    "valid IP address",
			host:    "192.168.1.1",
			wantErr: false,
		},
		{
			name:    "valid IPv6 address",
			host:    "[2001:db8::1]",
			wantErr: false,
		},
		{
			name:    "empty hostname",
			host:    "",
			wantErr: true,
		},
		{
			name:    "hostname too long",
			host:    strings.Repeat("a", MaxHostnameLength+1),
			wantErr: true,
		},
		{
			name:    "null byte in hostname",
			host:    "example\x00.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHostname(tt.host)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHostname() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCheckSuspiciousPatterns(t *testing.T) {
	tests := []struct {
		name             string
		request          *http.Request
		expectSuspicious bool
		minPatternCount  int
	}{
		{
			name: "clean request",
			request: &http.Request{
				Method: "GET",
				URL:    mustParseURL("https://example.com/api/users"),
				Header: http.Header{
					"User-Agent": []string{"Mozilla/5.0"},
				},
			},
			expectSuspicious: false,
			minPatternCount:  0,
		},
		{
			name: "SQL injection in query param",
			request: &http.Request{
				Method: "GET",
				URL:    mustParseURL("https://example.com/api/users?id=1' UNION SELECT * FROM users--"),
				Header: http.Header{},
			},
			expectSuspicious: true,
			minPatternCount:  1,
		},
		{
			name: "XSS attempt in query param",
			request: &http.Request{
				Method: "GET",
				URL:    mustParseURL("https://example.com/api/page?content=<script>alert('xss')</script>"),
				Header: http.Header{},
			},
			expectSuspicious: true,
			minPatternCount:  1,
		},
		{
			name: "command injection in header",
			request: &http.Request{
				Method: "GET",
				URL:    mustParseURL("https://example.com/api/users"),
				Header: http.Header{
					"X-Custom": []string{"value; rm -rf /"},
				},
			},
			expectSuspicious: true,
			minPatternCount:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &SecurityValidationResult{Valid: true}
			CheckSuspiciousPatterns(tt.request, result)

			hasSuspicious := len(result.SuspiciousPatterns) > 0
			if hasSuspicious != tt.expectSuspicious {
				t.Errorf("CheckSuspiciousPatterns() suspicious = %v, want %v", hasSuspicious, tt.expectSuspicious)
			}

			if len(result.SuspiciousPatterns) < tt.minPatternCount {
				t.Errorf("CheckSuspiciousPatterns() pattern count = %d, want at least %d", len(result.SuspiciousPatterns), tt.minPatternCount)
			}
		})
	}
}

func TestValidateRequest(t *testing.T) {
	tests := []struct {
		name    string
		request *http.Request
		wantErr bool
	}{
		{
			name: "valid request",
			request: &http.Request{
				Method: "GET",
				URL:    mustParseURL("https://example.com/api/users?page=1"),
				Host:   "example.com",
				Header: http.Header{
					"User-Agent":   []string{"Mozilla/5.0"},
					"Content-Type": []string{"application/json"},
				},
			},
			wantErr: false,
		},
		{
			name: "request with path traversal",
			request: &http.Request{
				Method: "GET",
				URL:    mustParseURL("https://example.com/../../../etc/passwd"),
				Host:   "example.com",
				Header: http.Header{},
			},
			wantErr: true,
		},
		{
			name: "request with header injection",
			request: &http.Request{
				Method: "GET",
				URL:    mustParseURL("https://example.com/api/users"),
				Host:   "example.com",
				Header: http.Header{
					"X-Custom": []string{"value\r\nInjected: header"},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateRequest(tt.request)
			if (result.Valid == false) != tt.wantErr {
				t.Errorf("ValidateRequest() valid = %v, wantErr %v", result.Valid, tt.wantErr)
			}
		})
	}
}

func TestSanitizeInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "clean input",
			input: "Hello World",
			want:  "Hello World",
		},
		{
			name:  "input with null bytes",
			input: "Hello\x00World",
			want:  "HelloWorld",
		},
		{
			name:  "input with CRLF",
			input: "Hello\r\nWorld",
			want:  "HelloWorld",
		},
		{
			name:  "input with control characters",
			input: "Hello\x01\x02\x03World",
			want:  "HelloWorld",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeInput(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeInput() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSanitizeHeader(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "clean header",
			input: "application/json",
			want:  "application/json",
		},
		{
			name:  "header with CRLF",
			input: "value\r\nInjected-Header: malicious",
			want:  "valueInjected-Header: malicious",
		},
		{
			name:  "header with null byte",
			input: "value\x00malicious",
			want:  "valuemalicious",
		},
		{
			name:  "header with whitespace",
			input: "  value  ",
			want:  "value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeHeader(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateContentType(t *testing.T) {
	allowedTypes := []string{"application/json", "application/xml", "text/plain"}

	tests := []struct {
		name        string
		contentType string
		wantErr     bool
	}{
		{
			name:        "allowed JSON",
			contentType: "application/json",
			wantErr:     false,
		},
		{
			name:        "allowed JSON with charset",
			contentType: "application/json; charset=utf-8",
			wantErr:     false,
		},
		{
			name:        "allowed XML",
			contentType: "application/xml",
			wantErr:     false,
		},
		{
			name:        "not allowed type",
			contentType: "text/html",
			wantErr:     true,
		},
		{
			name:        "empty content type",
			contentType: "",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateContentType(tt.contentType, allowedTypes)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateContentType() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsSecureScheme(t *testing.T) {
	tests := []struct {
		name   string
		scheme string
		want   bool
	}{
		{
			name:   "https",
			scheme: "https",
			want:   true,
		},
		{
			name:   "HTTPS uppercase",
			scheme: "HTTPS",
			want:   true,
		},
		{
			name:   "http",
			scheme: "http",
			want:   false,
		},
		{
			name:   "ftp",
			scheme: "ftp",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSecureScheme(tt.scheme)
			if got != tt.want {
				t.Errorf("IsSecureScheme() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetSecurityHeaders(t *testing.T) {
	headers := GetSecurityHeaders()

	// Check that essential security headers are present
	requiredHeaders := []string{
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"Referrer-Policy",
		"Permissions-Policy",
	}

	for _, header := range requiredHeaders {
		if _, ok := headers[header]; !ok {
			t.Errorf("GetSecurityHeaders() missing required header: %s", header)
		}
	}
}

func TestIsSuspiciousUserAgent(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		want      bool
	}{
		{
			name:      "normal browser",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
			want:      false,
		},
		{
			name:      "curl",
			userAgent: "curl/7.68.0",
			want:      true,
		},
		{
			name:      "wget",
			userAgent: "Wget/1.20.3",
			want:      true,
		},
		{
			name:      "python requests",
			userAgent: "python-requests/2.25.1",
			want:      true,
		},
		{
			name:      "bot",
			userAgent: "Googlebot/2.1",
			want:      true,
		},
		{
			name:      "empty user agent",
			userAgent: "",
			want:      true,
		},
		{
			name:      "XSS attempt",
			userAgent: "<script>alert('xss')</script>",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSuspiciousUserAgent(tt.userAgent)
			if got != tt.want {
				t.Errorf("IsSuspiciousUserAgent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateRequestMethod(t *testing.T) {
	allowedMethods := []string{"GET", "POST", "PUT", "DELETE"}

	tests := []struct {
		name    string
		method  string
		wantErr bool
	}{
		{
			name:    "allowed GET",
			method:  "GET",
			wantErr: false,
		},
		{
			name:    "allowed POST",
			method:  "POST",
			wantErr: false,
		},
		{
			name:    "not allowed TRACE",
			method:  "TRACE",
			wantErr: true,
		},
		{
			name:    "not allowed CONNECT",
			method:  "CONNECT",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRequestMethod(tt.method, allowedMethods)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRequestMethod() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateOrigin(t *testing.T) {
	allowedOrigins := []string{
		"https://example.com",
		"https://app.example.com",
		"*.trusted.com",
	}

	tests := []struct {
		name    string
		origin  string
		wantErr bool
	}{
		{
			name:    "allowed exact match",
			origin:  "https://example.com",
			wantErr: false,
		},
		{
			name:    "allowed subdomain exact match",
			origin:  "https://app.example.com",
			wantErr: false,
		},
		{
			name:    "allowed wildcard match",
			origin:  "https://api.trusted.com",
			wantErr: false,
		},
		{
			name:    "not allowed origin",
			origin:  "https://malicious.com",
			wantErr: true,
		},
		{
			name:    "empty origin",
			origin:  "",
			wantErr: false,
		},
		{
			name:    "invalid origin URL",
			origin:  "not a valid url",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateOrigin(tt.origin, allowedOrigins)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateOrigin() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRateLimitKey(t *testing.T) {
	tests := []struct {
		name   string
		ip     string
		userID string
		want   string
	}{
		{
			name:   "with user ID",
			ip:     "192.168.1.1",
			userID: "user123",
			want:   "ratelimit:user:user123",
		},
		{
			name:   "without user ID",
			ip:     "192.168.1.1",
			userID: "",
			want:   "ratelimit:ip:192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RateLimitKey(tt.ip, tt.userID)
			if got != tt.want {
				t.Errorf("RateLimitKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Helper function to parse URLs in tests
func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return u
}

// Benchmark tests for performance validation
func BenchmarkValidateRequest(b *testing.B) {
	b.ReportAllocs()
	req := &http.Request{
		Method: "GET",
		URL:    mustParseURL("https://example.com/api/users?page=1&limit=10"),
		Host:   "example.com",
		Header: http.Header{
			"User-Agent":   []string{"Mozilla/5.0"},
			"Content-Type": []string{"application/json"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidateRequest(req)
	}
}

func BenchmarkCheckSuspiciousPatterns(b *testing.B) {
	b.ReportAllocs()
	req := &http.Request{
		Method: "GET",
		URL:    mustParseURL("https://example.com/api/users?name=John&age=30"),
		Host:   "example.com",
		Header: http.Header{
			"User-Agent": []string{"Mozilla/5.0"},
		},
	}

	result := &SecurityValidationResult{Valid: true}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckSuspiciousPatterns(req, result)
	}
}

func BenchmarkSanitizeInput(b *testing.B) {
	b.ReportAllocs()
	input := "Hello World with some text that needs sanitization"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SanitizeInput(input)
	}
}
