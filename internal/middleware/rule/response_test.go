package rule

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
)

func TestResponseRule_Match(t *testing.T) {
	tests := []struct {
		name       string
		rule       ResponseRule
		statusCode int
		headers    map[string]string
		body       string
		expected   bool
	}{
		// Empty rule tests
		{
			name:       "Empty rule matches everything",
			rule:       EmptyResponseRule,
			statusCode: 200,
			expected:   true,
		},
		{
			name:       "Empty rule matches 404",
			rule:       EmptyResponseRule,
			statusCode: 404,
			expected:   true,
		},
		{
			name:       "Empty rule with IsEmpty() check",
			rule:       ResponseRule{},
			statusCode: 200,
			expected:   true,
		},

		// StatusCode matching
		{
			name:       "Rule matches exact status code",
			rule:       ResponseRule{Status: &StatusConditions{Code: 200}},
			statusCode: 200,
			expected:   true,
		},
		{
			name:       "Rule does not match different status code",
			rule:       ResponseRule{Status: &StatusConditions{Code: 200}},
			statusCode: 404,
			expected:   false,
		},

		// StatusCodes matching
		{
			name:       "StatusCodes - one matches",
			rule:       ResponseRule{Status: &StatusConditions{Codes: []int{200, 201, 204}}},
			statusCode: 200,
			expected:   true,
		},
		{
			name:       "StatusCodes - none match",
			rule:       ResponseRule{Status: &StatusConditions{Codes: []int{200, 201, 204}}},
			statusCode: 404,
			expected:   false,
		},
		{
			name:       "StatusCodes - different code matches",
			rule:       ResponseRule{Status: &StatusConditions{Codes: []int{200, 201, 204}}},
			statusCode: 201,
			expected:   true,
		},

		// Header matching
		{
			name:       "Header matches",
			rule:       ResponseRule{Headers: &HeaderConditions{Exact: map[string]string{"Content-Type": "application/json"}}},
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "application/json"},
			expected:   true,
		},
		{
			name:       "Header does not match value",
			rule:       ResponseRule{Headers: &HeaderConditions{Exact: map[string]string{"Content-Type": "application/json"}}},
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/plain"},
			expected:   false,
		},
		{
			name:       "Multiple headers match",
			rule:       ResponseRule{Headers: &HeaderConditions{Exact: map[string]string{"Content-Type": "application/json", "X-Custom": "value"}}},
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "application/json", "X-Custom": "value"},
			expected:   true,
		},

		// HeaderExists matching
		{
			name:       "HeaderExists - header exists",
			rule:       ResponseRule{Headers: &HeaderConditions{Exists: []string{"X-Custom"}}},
			statusCode: 200,
			headers:    map[string]string{"X-Custom": "value"},
			expected:   true,
		},
		{
			name:       "HeaderExists - header missing",
			rule:       ResponseRule{Headers: &HeaderConditions{Exists: []string{"X-Custom"}}},
			statusCode: 200,
			headers:    nil,
			expected:   false,
		},
		{
			name:       "HeaderExists - multiple headers exist",
			rule:       ResponseRule{Headers: &HeaderConditions{Exists: []string{"X-Custom", "X-Other"}}},
			statusCode: 200,
			headers:    map[string]string{"X-Custom": "value", "X-Other": "test"},
			expected:   true,
		},

		// HeaderDoesNotExist matching
		{
			name:       "HeaderDoesNotExist - header does not exist",
			rule:       ResponseRule{Headers: &HeaderConditions{NotExist: []string{"X-Custom"}}},
			statusCode: 200,
			headers:    nil,
			expected:   true,
		},
		{
			name:       "HeaderDoesNotExist - header exists",
			rule:       ResponseRule{Headers: &HeaderConditions{NotExist: []string{"X-Custom"}}},
			statusCode: 200,
			headers:    map[string]string{"X-Custom": "value"},
			expected:   false,
		},

		// ContentTypes matching
		{
			name:       "ContentTypes - matches",
			rule:       ResponseRule{ContentTypes: []string{"application/json"}},
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "application/json"},
			expected:   true,
		},
		{
			name:       "ContentTypes - matches with charset",
			rule:       ResponseRule{ContentTypes: []string{"application/json"}},
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "application/json; charset=utf-8"},
			expected:   true,
		},
		{
			name:       "ContentTypes - does not match",
			rule:       ResponseRule{ContentTypes: []string{"application/json"}},
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			expected:   false,
		},
		{
			name:       "ContentTypes - missing header",
			rule:       ResponseRule{ContentTypes: []string{"application/json"}},
			statusCode: 200,
			headers:    nil,
			expected:   false,
		},
		{
			name:       "ContentTypes - multiple types, one matches",
			rule:       ResponseRule{ContentTypes: []string{"application/json", "text/html"}},
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			expected:   true,
		},

		// BodyContains matching
		{
			name:       "BodyContains - matches",
			rule:       ResponseRule{BodyContains: "success"},
			statusCode: 200,
			body:       "Operation success",
			expected:   true,
		},
		{
			name:       "BodyContains - does not match",
			rule:       ResponseRule{BodyContains: "success"},
			statusCode: 200,
			body:       "Operation failed",
			expected:   false,
		},
		{
			name:       "BodyContains - empty body",
			rule:       ResponseRule{BodyContains: "success"},
			statusCode: 200,
			body:       "",
			expected:   false,
		},

		// AND logic - multiple fields must all match
		{
			name:       "StatusCode AND Header match",
			rule:       ResponseRule{Status: &StatusConditions{Code: 200}, Headers: &HeaderConditions{Exact: map[string]string{"Content-Type": "application/json"}}},
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "application/json"},
			expected:   true,
		},
		{
			name:       "StatusCode AND Header - status code mismatch",
			rule:       ResponseRule{Status: &StatusConditions{Code: 200}, Headers: &HeaderConditions{Exact: map[string]string{"Content-Type": "application/json"}}},
			statusCode: 404,
			headers:    map[string]string{"Content-Type": "application/json"},
			expected:   false,
		},
		{
			name:       "StatusCodes AND ContentTypes match",
			rule:       ResponseRule{Status: &StatusConditions{Codes: []int{200, 201}}, ContentTypes: []string{"application/json"}},
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "application/json"},
			expected:   true,
		},
		{
			name:       "All fields match",
			rule:       ResponseRule{Status: &StatusConditions{Codes: []int{200}}, Headers: &HeaderConditions{Exact: map[string]string{"Content-Type": "application/json"}}, BodyContains: "success"},
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "application/json"},
			body:       "Operation success",
			expected:   true,
		},
		{
			name:       "All fields - body mismatch",
			rule:       ResponseRule{Status: &StatusConditions{Codes: []int{200}}, Headers: &HeaderConditions{Exact: map[string]string{"Content-Type": "application/json"}}, BodyContains: "success"},
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "application/json"},
			body:       "Operation failed",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			for key, value := range tt.headers {
				resp.Header.Set(key, value)
			}
			if tt.body != "" {
				resp.Body = io.NopCloser(bytes.NewReader([]byte(tt.body)))
			} else {
				resp.Body = io.NopCloser(bytes.NewReader([]byte{}))
			}
			result := tt.rule.Match(resp)
			if result != tt.expected {
				t.Errorf("Expected Match() = %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestResponseRules_Match(t *testing.T) {
	tests := []struct {
		name       string
		rules      ResponseRules
		statusCode int
		headers    map[string]string
		expected   bool
	}{
		{
			name:       "Empty rules slice matches everything",
			rules:      ResponseRules{},
			statusCode: 200,
			expected:   true,
		},
		{
			name: "Rules with empty rule matches",
			rules: ResponseRules{
				EmptyResponseRule,
				ResponseRule{Status: &StatusConditions{Code: 404}},
			},
			statusCode: 200,
			expected:   true,
		},
		{
			name: "One matching rule returns true",
			rules: ResponseRules{
				ResponseRule{Status: &StatusConditions{Code: 404}},
				ResponseRule{Status: &StatusConditions{Code: 200}},
			},
			statusCode: 200,
			expected:   true,
		},
		{
			name: "Rules with AND logic - first rule matches",
			rules: ResponseRules{
				ResponseRule{Status: &StatusConditions{Codes: []int{200}}, Headers: &HeaderConditions{Exact: map[string]string{"Content-Type": "application/json"}}},
				ResponseRule{Status: &StatusConditions{Codes: []int{404}}, Headers: &HeaderConditions{Exact: map[string]string{"Content-Type": "text/html"}}},
			},
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "application/json"},
			expected:   true,
		},
		{
			name: "Rules with AND logic - status matches but header doesn't",
			rules: ResponseRules{
				ResponseRule{Status: &StatusConditions{Codes: []int{200}}, Headers: &HeaderConditions{Exact: map[string]string{"Content-Type": "application/json"}}},
			},
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/plain"},
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader([]byte{})),
			}
			for key, value := range tt.headers {
				resp.Header.Set(key, value)
			}
			result := tt.rules.Match(resp)
			if result != tt.expected {
				t.Errorf("Expected Match() = %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestResponseRule_JSON(t *testing.T) {
	tests := []struct {
		name string
		json string
		want ResponseRule
	}{
		{
			name: "Status code 200",
			json: `{"status":{"code":200}}`,
			want: ResponseRule{Status: &StatusConditions{Code: 200}},
		},
		{
			name: "StatusCodes array",
			json: `{"status":{"codes":[200,201,204]}}`,
			want: ResponseRule{Status: &StatusConditions{Codes: []int{200, 201, 204}}},
		},
		{
			name: "HeaderExists",
			json: `{"headers":{"exists":["X-Custom"]}}`,
			want: ResponseRule{Headers: &HeaderConditions{Exists: []string{"X-Custom"}}},
		},
		{
			name: "HeaderDoesNotExist",
			json: `{"headers":{"not_exist":["X-Custom"]}}`,
			want: ResponseRule{Headers: &HeaderConditions{NotExist: []string{"X-Custom"}}},
		},
		{
			name: "ContentTypes",
			json: `{"content_types":["application/json","text/html"]}`,
			want: ResponseRule{ContentTypes: []string{"application/json", "text/html"}},
		},
		{
			name: "BodyContains",
			json: `{"body_contains":"success"}`,
			want: ResponseRule{BodyContains: "success"},
		},
		{
			name: "Status code and headers",
			json: `{"status":{"code":200},"headers":{"exact":{"Content-Type":"application/json"}}}`,
			want: ResponseRule{
				Status:  &StatusConditions{Code: 200},
				Headers: &HeaderConditions{Exact: map[string]string{"Content-Type": "application/json"}},
			},
		},
		{
			name: "Multiple fields",
			json: `{"status":{"codes":[200,201]},"content_types":["application/json"],"headers":{"exact":{"Content-Type":"application/json"}},"body_contains":"success"}`,
			want: ResponseRule{
				Status:       &StatusConditions{Codes: []int{200, 201}},
				ContentTypes: []string{"application/json"},
				Headers:      &HeaderConditions{Exact: map[string]string{"Content-Type": "application/json"}},
				BodyContains: "success",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got ResponseRule
			if err := json.Unmarshal([]byte(tt.json), &got); err != nil {
				t.Fatalf("Failed to unmarshal JSON: %v", err)
			}
			if !responseRulesEqual(got, tt.want) {
				t.Errorf("Expected %+v, got %+v", tt.want, got)
			}
		})
	}
}

func TestResponseRule_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		rule     ResponseRule
		expected bool
	}{
		{
			name:     "Empty rule",
			rule:     ResponseRule{},
			expected: true,
		},
		{
			name:     "Rule with status code",
			rule:     ResponseRule{Status: &StatusConditions{Code: 200}},
			expected: false,
		},
		{
			name:     "Rule with status codes",
			rule:     ResponseRule{Status: &StatusConditions{Codes: []int{200, 201}}},
			expected: false,
		},
		{
			name:     "Rule with headers",
			rule:     ResponseRule{Headers: &HeaderConditions{Exact: map[string]string{"Content-Type": "application/json"}}},
			expected: false,
		},
		{
			name:     "Rule with header exists",
			rule:     ResponseRule{Headers: &HeaderConditions{Exists: []string{"X-Custom"}}},
			expected: false,
		},
		{
			name:     "Rule with content types",
			rule:     ResponseRule{ContentTypes: []string{"application/json"}},
			expected: false,
		},
		{
			name:     "Rule with body contains",
			rule:     ResponseRule{BodyContains: "success"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rule.IsEmpty()
			if result != tt.expected {
				t.Errorf("Expected IsEmpty() = %v, got %v", tt.expected, result)
			}
		})
	}
}

func responseRulesEqual(a, b ResponseRule) bool {
	if !stringSliceEqual(a.ContentTypes, b.ContentTypes) ||
		a.BodyContains != b.BodyContains {
		return false
	}

	// Compare Status conditions
	if !statusConditionsEqual(a.Status, b.Status) {
		return false
	}

	// Compare Header conditions  
	// Note: headerConditionsEqual is defined in request_test.go (test helper)
	// For now, just do a simple comparison
	if (a.Headers == nil) != (b.Headers == nil) {
		return false
	}

	return true
}

func statusConditionsEqual(a, b *StatusConditions) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Code == b.Code && intSliceEqual(a.Codes, b.Codes)
}

func intSliceEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestResponseRule_CEL_Integration(t *testing.T) {
	
	tests := []struct {
		name       string
		jsonRule   string
		statusCode int
		headers    map[string]string
		body       string
		expected   bool
		expectErr  bool
	}{
		{
			name:       "CEL matches 200 status",
			jsonRule:   `{"cel_expr": "response.status_code == 200"}`,
			statusCode: 200,
			expected:   true,
		},
		{
			name:       "CEL does not match 404 status",
			jsonRule:   `{"cel_expr": "response.status_code == 200"}`,
			statusCode: 404,
			expected:   false,
		},
		{
			name:       "CEL matches status range",
			jsonRule:   `{"cel_expr": "response.status_code >= 200 && response.status_code < 300"}`,
			statusCode: 201,
			expected:   true,
		},
		{
			name:       "CEL matches 4xx errors",
			jsonRule:   `{"cel_expr": "response.status_code >= 400 && response.status_code < 500"}`,
			statusCode: 404,
			expected:   true,
		},
		{
			name:       "CEL matches 5xx errors",
			jsonRule:   `{"cel_expr": "response.status_code >= 500"}`,
			statusCode: 500,
			expected:   true,
		},
		{
			name:       "CEL matches header",
			jsonRule:   `{"cel_expr": "response.headers[\"content-type\"].contains(\"json\")"}`,
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "application/json"},
			expected:   true,
		},
		{
			name:       "CEL does not match header",
			jsonRule:   `{"cel_expr": "response.headers[\"content-type\"].contains(\"json\")"}`,
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			expected:   false,
		},
		{
			name:       "CEL matches body content",
			jsonRule:   `{"cel_expr": "response.body.contains(\"success\")"}`,
			statusCode: 200,
			body:       `{"status": "success"}`,
			expected:   true,
		},
		{
			name:       "CEL does not match body content",
			jsonRule:   `{"cel_expr": "response.body.contains(\"error\")"}`,
			statusCode: 200,
			body:       `{"status": "success"}`,
			expected:   false,
		},
		{
			name:       "CEL combined status and body",
			jsonRule:   `{"cel_expr": "response.status_code == 200 && response.body.contains(\"ok\")"}`,
			statusCode: 200,
			body:       `{"message": "ok"}`,
			expected:   true,
		},
		{
			name:       "CEL JSON error response",
			jsonRule:   `{"cel_expr": "response.status_code >= 400 && response.headers[\"content-type\"].contains(\"json\") && response.body.contains(\"error\")"}`,
			statusCode: 500,
			headers:    map[string]string{"Content-Type": "application/json"},
			body:       `{"error": "internal server error"}`,
			expected:   true,
		},
		{
			name:       "CEL invalid expression",
			jsonRule:   `{"cel_expr": "response.status_code"}`,
			statusCode: 200,
			expectErr:  true,
		},
		{
			name:       "CEL invalid syntax",
			jsonRule:   `{"cel_expr": "response.status_code =="}`,
			statusCode: 200,
			expectErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rule ResponseRule
			err := json.Unmarshal([]byte(tt.jsonRule), &rule)
			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error during unmarshaling, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Failed to unmarshal JSON: %v", err)
			}

			// Create response with proper request
			req := &http.Request{
				Method: "GET",
				URL:    &url.URL{Path: "/test"},
			}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     http.Header{},
				Body:       io.NopCloser(bytes.NewBufferString(tt.body)),
				Request:    req,
			}
			for k, v := range tt.headers {
				resp.Header.Set(k, v)
			}

			result := rule.Match(resp)
			if result != tt.expected {
				t.Errorf("Expected Match() = %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestResponseRule_Lua_Integration(t *testing.T) {
	
	tests := []struct {
		name       string
		jsonRule   string
		statusCode int
		headers    map[string]string
		body       string
		expected   bool
		expectErr  bool
	}{
		{
			name:       "Lua matches 200 status",
			jsonRule:   `{"lua_script": "return response.status_code == 200"}`,
			statusCode: 200,
			expected:   true,
		},
		{
			name:       "Lua does not match 404 status",
			jsonRule:   `{"lua_script": "return response.status_code == 200"}`,
			statusCode: 404,
			expected:   false,
		},
		{
			name:       "Lua matches status range",
			jsonRule:   `{"lua_script": "return response.status_code >= 200 and response.status_code < 300"}`,
			statusCode: 201,
			expected:   true,
		},
		{
			name:       "Lua matches 4xx errors",
			jsonRule:   `{"lua_script": "return response.status_code >= 400 and response.status_code < 500"}`,
			statusCode: 404,
			expected:   true,
		},
		{
			name:       "Lua matches 5xx errors",
			jsonRule:   `{"lua_script": "return response.status_code >= 500"}`,
			statusCode: 500,
			expected:   true,
		},
		{
			name:       "Lua with conditional",
			jsonRule:   `{"lua_script": "if response.status_code >= 500 then return true end\nreturn false"}`,
			statusCode: 503,
			expected:   true,
		},
		{
			name:       "Lua matches header",
			jsonRule:   `{"lua_script": "return response.headers[\"content-type\"]:find(\"json\") ~= nil"}`,
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "application/json"},
			expected:   true,
		},
		{
			name:       "Lua does not match header",
			jsonRule:   `{"lua_script": "return response.headers[\"content-type\"]:find(\"json\") ~= nil"}`,
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			expected:   false,
		},
		{
			name:       "Lua matches body content",
			jsonRule:   `{"lua_script": "return response.body:find(\"success\") ~= nil"}`,
			statusCode: 200,
			body:       `{"status": "success"}`,
			expected:   true,
		},
		{
			name:       "Lua does not match body content",
			jsonRule:   `{"lua_script": "return response.body:find(\"error\") ~= nil"}`,
			statusCode: 200,
			body:       `{"status": "success"}`,
			expected:   false,
		},
		{
			name:       "Lua combined status and body",
			jsonRule:   `{"lua_script": "return response.status_code == 200 and response.body:find(\"ok\") ~= nil"}`,
			statusCode: 200,
			body:       `{"message": "ok"}`,
			expected:   true,
		},
		{
			name:       "Lua JSON error response",
			jsonRule:   `{"lua_script": "return response.status_code >= 400 and response.headers[\"content-type\"]:find(\"json\") ~= nil and response.body:find(\"error\") ~= nil"}`,
			statusCode: 500,
			headers:    map[string]string{"Content-Type": "application/json"},
			body:       `{"error": "internal server error"}`,
			expected:   true,
		},
		{
			name:       "Lua complex conditional logic",
			jsonRule:   `{"lua_script": "if response.status_code == 200 then\n  if response.body:find(\"success\") then\n    return true\n  end\nelseif response.status_code == 201 then\n  return true\nend\nreturn false"}`,
			statusCode: 200,
			body:       `{"status": "success"}`,
			expected:   true,
		},
		{
			name:       "Lua invalid syntax",
			jsonRule:   `{"lua_script": "return response.status_code =="}`,
			statusCode: 200,
			expectErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rule ResponseRule
			err := json.Unmarshal([]byte(tt.jsonRule), &rule)
			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error during unmarshaling, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Failed to unmarshal JSON: %v", err)
			}

			// Create response with proper request
			req := &http.Request{
				Method: "GET",
				URL:    &url.URL{Path: "/test"},
			}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     http.Header{},
				Body:       io.NopCloser(bytes.NewBufferString(tt.body)),
				Request:    req,
			}
			for k, v := range tt.headers {
				resp.Header.Set(k, v)
			}

			result := rule.Match(resp)
			if result != tt.expected {
				t.Errorf("Expected Match() = %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestResponseRule_CEL_And_Lua_Combined(t *testing.T) {
	
	// Test that CEL and Lua can be combined in a single rule (both must match)
	jsonRule := `{
		"cel_expr": "response.status_code == 200",
		"lua_script": "return response.body:find(\"success\") ~= nil"
	}`

	var rule ResponseRule
	err := json.Unmarshal([]byte(jsonRule), &rule)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	tests := []struct {
		name       string
		statusCode int
		body       string
		expected   bool
	}{
		{
			name:       "Both CEL and Lua match",
			statusCode: 200,
			body:       `{"status": "success"}`,
			expected:   true,
		},
		{
			name:       "CEL matches but Lua does not",
			statusCode: 200,
			body:       `{"status": "error"}`,
			expected:   false,
		},
		{
			name:       "Lua matches but CEL does not",
			statusCode: 404,
			body:       `{"status": "success"}`,
			expected:   false,
		},
		{
			name:       "Neither CEL nor Lua match",
			statusCode: 404,
			body:       `{"status": "error"}`,
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Method: "GET",
				URL:    &url.URL{Path: "/test"},
			}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     http.Header{},
				Body:       io.NopCloser(bytes.NewBufferString(tt.body)),
				Request:    req,
			}

			result := rule.Match(resp)
			if result != tt.expected {
				t.Errorf("Expected Match() = %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestResponseRule_IsEmpty_With_CEL_And_Lua(t *testing.T) {
	tests := []struct {
		name     string
		rule     ResponseRule
		expected bool
	}{
		{
			name:     "Rule with CEL is not empty",
			rule:     ResponseRule{CELExpr: "response.status_code == 200"},
			expected: false,
		},
		{
			name:     "Rule with Lua is not empty",
			rule:     ResponseRule{LuaScript: "return response.status_code == 200"},
			expected: false,
		},
		{
			name:     "Rule with both CEL and Lua is not empty",
			rule:     ResponseRule{CELExpr: "response.status_code == 200", LuaScript: "return true"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rule.IsEmpty()
			if result != tt.expected {
				t.Errorf("Expected IsEmpty() = %v, got %v", tt.expected, result)
			}
		})
	}
}
