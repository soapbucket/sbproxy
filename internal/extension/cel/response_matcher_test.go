package cel

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
		expr    string
		wantErr bool
		errType error
	}{
		{
			name:    "valid status code check",
			expr:    "response.status_code == 200",
			wantErr: false,
		},
		{
			name:    "valid header check",
			expr:    `response.headers["Content-Type"].contains("json")`,
			wantErr: false,
		},
		{
			name:    "valid body check",
			expr:    `response.body.contains("success")`,
			wantErr: false,
		},
		{
			name:    "valid combined check",
			expr:    `response.status_code == 200 && response.body.contains("ok")`,
			wantErr: false,
		},
		{
			name:    "valid request context check",
			expr:    `response.status_code == 404 && request.path.startsWith("/api/")`,
			wantErr: false,
		},
		{
			name:    "invalid - non-boolean return",
			expr:    `response.status_code`,
			wantErr: true,
			errType: ErrWrongType,
		},
		{
			name:    "invalid syntax",
			expr:    `response.status_code ==`,
			wantErr: true,
		},
		{
			name:    "empty expression",
			expr:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewResponseMatcher(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewResponseMatcher() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.errType != nil && err != tt.errType {
				t.Errorf("NewResponseMatcher() error type = %T, want %T", err, tt.errType)
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
		expr     string
		resp     *http.Response
		expected bool
	}{
		{
			name: "match status code 200",
			expr: "response.status_code == 200",
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
			name: "not match status code",
			expr: "response.status_code == 404",
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
			name: "match status code range",
			expr: "response.status_code >= 200 && response.status_code < 300",
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
			name: "match 4xx errors",
			expr: "response.status_code >= 400 && response.status_code < 500",
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
			name: "match 5xx errors",
			expr: "response.status_code >= 500",
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
			name: "match header",
			expr: `response.headers["content-type"].contains("application/json")`,
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
			name: "not match header",
			expr: `response.headers["content-type"].contains("text/html")`,
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
			name: "match body content",
			expr: `response.body.contains("success")`,
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
			name: "not match body content",
			expr: `response.body.contains("error")`,
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
			name: "combined status and body",
			expr: `response.status_code == 200 && response.body.contains("ok")`,
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
			name: "match with request path",
			expr: `response.status_code == 404 && request.path.startsWith("/api/")`,
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
			name: "not match with request path",
			expr: `response.status_code == 404 && request.path.startsWith("/api/")`,
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
			name: "match with request method",
			expr: `response.status_code >= 400 && request.method == "POST"`,
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
			expr: `response.status_code >= 400 && response.headers["content-type"].contains("json") && response.body.contains("error")`,
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
			name: "empty body",
			expr: `response.status_code == 204 && response.body == ""`,
			resp: &http.Response{
				StatusCode: 204,
				Status:     "204 No Content",
				Header:     http.Header{},
				Body:       io.NopCloser(bytes.NewBufferString("")),
				Request:    httptest.NewRequest("DELETE", "/api/resource", nil),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewResponseMatcher(tt.expr)
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
		expr     string
		expected bool
	}{
		{
			name:     "match with request path",
			expr:     `response.status_code == 200 && request.path.startsWith("/api/")`,
			expected: true,
		},
		{
			name:     "combined response and request context",
			expr:     `response.status_code == 200 && request.path.startsWith("/api/") && request.method == "GET"`,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewResponseMatcher(tt.expr)
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

func BenchmarkResponseMatcher_Match(b *testing.B) {
	b.ReportAllocs()
	matcher, err := NewResponseMatcher(`response.status_code == 200 && response.body.contains("success")`)
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

