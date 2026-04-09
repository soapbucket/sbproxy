package lua

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewResponseMatcher(t *testing.T) {
	tests := []struct {
		name    string
		script  string
		wantErr bool
	}{
		{
			name:    "valid status code check",
			script:  "return response.status_code == 200",
			wantErr: false,
		},
		{
			name:    "valid header check",
			script:  `return response.headers["Content-Type"]:find("json") ~= nil`,
			wantErr: false,
		},
		{
			name:    "valid body check",
			script:  `return response.body:find("success") ~= nil`,
			wantErr: false,
		},
		{
			name: "valid multi-line script",
			script: `
				if response.status_code >= 500 then
					return true
				end
				return false
			`,
			wantErr: false,
		},
		{
			name:    "empty script",
			script:  "",
			wantErr: true,
		},
		{
			name:    "invalid syntax",
			script:  "return response.status_code ==",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewResponseMatcher(tt.script)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewResponseMatcher() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && matcher == nil {
				t.Error("NewResponseMatcher() returned nil matcher without error")
			}
		})
	}
}

func TestResponseMatcher_Match(t *testing.T) {
	tests := []struct {
		name     string
		script   string
		resp     *http.Response
		expected bool
	}{
		{
			name:   "match status code 200",
			script: "return response.status_code == 200",
			resp: &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header:     http.Header{},
				Body:       io.NopCloser(bytes.NewBufferString("")),
				Request:    httptest.NewRequest("GET", "/test", nil),
			},
			expected: true,
		},
		{
			name:   "not match status code",
			script: "return response.status_code == 404",
			resp: &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header:     http.Header{},
				Body:       io.NopCloser(bytes.NewBufferString("")),
				Request:    httptest.NewRequest("GET", "/test", nil),
			},
			expected: false,
		},
		{
			name:   "match status code range",
			script: "return response.status_code >= 200 and response.status_code < 300",
			resp: &http.Response{
				StatusCode: 201,
				Status:     "201 Created",
				Header:     http.Header{},
				Body:       io.NopCloser(bytes.NewBufferString("")),
				Request:    httptest.NewRequest("GET", "/test", nil),
			},
			expected: true,
		},
		{
			name:   "match 4xx errors",
			script: "return response.status_code >= 400 and response.status_code < 500",
			resp: &http.Response{
				StatusCode: 404,
				Status:     "404 Not Found",
				Header:     http.Header{},
				Body:       io.NopCloser(bytes.NewBufferString("")),
				Request:    httptest.NewRequest("GET", "/test", nil),
			},
			expected: true,
		},
		{
			name:   "match 5xx errors",
			script: "return response.status_code >= 500",
			resp: &http.Response{
				StatusCode: 500,
				Status:     "500 Internal Server Error",
				Header:     http.Header{},
				Body:       io.NopCloser(bytes.NewBufferString("Server error")),
				Request:    httptest.NewRequest("GET", "/test", nil),
			},
			expected: true,
		},
		{
			name: "match 5xx with conditional",
			script: `
				if response.status_code >= 500 then
					return true
				end
				return false
			`,
			resp: &http.Response{
				StatusCode: 503,
				Status:     "503 Service Unavailable",
				Header:     http.Header{},
				Body:       io.NopCloser(bytes.NewBufferString("")),
				Request:    httptest.NewRequest("GET", "/test", nil),
			},
			expected: true,
		},
		{
			name:   "match header",
			script: `return response.headers["content-type"]:find("application/json") ~= nil`,
			resp: &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header: http.Header{
					"Content-Type": []string{"application/json; charset=utf-8"},
				},
				Body:    io.NopCloser(bytes.NewBufferString("{}")),
				Request: httptest.NewRequest("GET", "/test", nil),
			},
			expected: true,
		},
		{
			name:   "not match header",
			script: `return response.headers["content-type"]:find("text/html") ~= nil`,
			resp: &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
				Body:    io.NopCloser(bytes.NewBufferString("{}")),
				Request: httptest.NewRequest("GET", "/test", nil),
			},
			expected: false,
		},
		{
			name:   "match body content",
			script: `return response.body:find("success") ~= nil`,
			resp: &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header:     http.Header{},
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "success"}`)),
				Request:    httptest.NewRequest("GET", "/test", nil),
			},
			expected: true,
		},
		{
			name:   "not match body content",
			script: `return response.body:find("error") ~= nil`,
			resp: &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header:     http.Header{},
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "success"}`)),
				Request:    httptest.NewRequest("GET", "/test", nil),
			},
			expected: false,
		},
		{
			name:   "combined status and body",
			script: `return response.status_code == 200 and response.body:find("ok") ~= nil`,
			resp: &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header:     http.Header{},
				Body:       io.NopCloser(bytes.NewBufferString(`{"message": "ok"}`)),
				Request:    httptest.NewRequest("GET", "/test", nil),
			},
			expected: true,
		},
		{
			name:   "match with request path",
			script: `return response.status_code == 404 and request.path:sub(1, 5) == "/api/"`,
			resp: &http.Response{
				StatusCode: 404,
				Status:     "404 Not Found",
				Header:     http.Header{},
				Body:       io.NopCloser(bytes.NewBufferString("")),
				Request:    httptest.NewRequest("GET", "/api/users", nil),
			},
			expected: true,
		},
		{
			name:   "not match with request path",
			script: `return response.status_code == 404 and request.path:sub(1, 5) == "/api/"`,
			resp: &http.Response{
				StatusCode: 404,
				Status:     "404 Not Found",
				Header:     http.Header{},
				Body:       io.NopCloser(bytes.NewBufferString("")),
				Request:    httptest.NewRequest("GET", "/public/page", nil),
			},
			expected: false,
		},
		{
			name:   "match with request method",
			script: `return response.status_code >= 400 and request.method == "POST"`,
			resp: &http.Response{
				StatusCode: 400,
				Status:     "400 Bad Request",
				Header:     http.Header{},
				Body:       io.NopCloser(bytes.NewBufferString("")),
				Request:    httptest.NewRequest("POST", "/api/submit", nil),
			},
			expected: true,
		},
		{
			name: "match JSON error response",
			script: `
				return response.status_code >= 400 and 
				       response.headers["content-type"]:find("json") ~= nil and 
				       response.body:find("error") ~= nil
			`,
			resp: &http.Response{
				StatusCode: 500,
				Status:     "500 Internal Server Error",
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
				Body:    io.NopCloser(bytes.NewBufferString(`{"error": "internal server error"}`)),
				Request: httptest.NewRequest("GET", "/api/data", nil),
			},
			expected: true,
		},
		{
			name:   "empty body",
			script: `return response.status_code == 204 and response.body == ""`,
			resp: &http.Response{
				StatusCode: 204,
				Status:     "204 No Content",
				Header:     http.Header{},
				Body:       io.NopCloser(bytes.NewBufferString("")),
				Request:    httptest.NewRequest("DELETE", "/api/resource", nil),
			},
			expected: true,
		},
		{
			name: "complex conditional logic",
			script: `
				if response.status_code == 200 then
					if response.body:find("success") then
						return true
					end
				elseif response.status_code == 201 then
					return true
				end
				return false
			`,
			resp: &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header:     http.Header{},
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "success"}`)),
				Request:    httptest.NewRequest("GET", "/test", nil),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewResponseMatcher(tt.script)
			if err != nil {
				t.Fatalf("NewResponseMatcher() error = %v", err)
			}

			result := matcher.Match(tt.resp)
			if result != tt.expected {
				t.Errorf("Match() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestResponseMatcher_Match_WithContext(t *testing.T) {
	// Test with request context variables (cookies, params, etc.)
	req := httptest.NewRequest("GET", "/api/users?status=active", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})

	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body:    io.NopCloser(bytes.NewBufferString(`{"users": []}`)),
		Request: req,
	}

	tests := []struct {
		name     string
		script   string
		expected bool
	}{
		{
			name:     "match with query param",
			script:   `return response.status_code == 200 and params["status"] == "active"`,
			expected: true,
		},
		{
			name:     "match with cookie",
			script:   `return response.status_code == 200 and cookies["session"] == "abc123"`,
			expected: true,
		},
		{
			name: "combined response and request context",
			script: `
				return response.status_code == 200 and 
				       request.path:sub(1, 5) == "/api/" and 
				       params["status"] == "active"
			`,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewResponseMatcher(tt.script)
			if err != nil {
				t.Fatalf("NewResponseMatcher() error = %v", err)
			}

			result := matcher.Match(resp)
			if result != tt.expected {
				t.Errorf("Match() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestResponseMatcher_InvalidReturn(t *testing.T) {
	tests := []struct {
		name   string
		script string
	}{
		{
			name:   "returns number instead of boolean",
			script: "return response.status_code",
		},
		{
			name:   "returns string instead of boolean",
			script: `return "true"`,
		},
		{
			name:   "returns table instead of boolean",
			script: "return {}",
		},
		{
			name:   "no return value",
			script: "local x = 1",
		},
	}

	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewBufferString("")),
		Request:    httptest.NewRequest("GET", "/test", nil),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewResponseMatcher(tt.script)
			if err != nil {
				t.Fatalf("NewResponseMatcher() error = %v", err)
			}

			result := matcher.Match(resp)
			if result != false {
				t.Errorf("Match() = %v, want false for invalid return", result)
			}
		})
	}
}

func BenchmarkResponseMatcher_Match(b *testing.B) {
	b.ReportAllocs()
	matcher, err := NewResponseMatcher(`return response.status_code == 200 and response.body:find("success") ~= nil`)
	if err != nil {
		b.Fatalf("NewResponseMatcher() error = %v", err)
	}

	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewBufferString(`{"status": "success", "data": {}}`)),
		Request:    httptest.NewRequest("GET", "/test", nil),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Reset body for each iteration
		resp.Body = io.NopCloser(bytes.NewBufferString(`{"status": "success", "data": {}}`))
		matcher.Match(resp)
	}
}
