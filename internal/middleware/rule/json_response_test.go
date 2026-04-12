package rule

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

func TestJSONResponseConditions_Match(t *testing.T) {
	tests := []struct {
		name     string
		rule     JSONResponseConditions
		resp     *http.Response
		expected bool
	}{
		// Field matching
		{
			name: "Fields - any matches",
			rule: JSONResponseConditions{
				Fields: []string{"user", "post"},
			},
			resp:     createJSONResponse(200, `{"user":{"id":"1"}}`, t),
			expected: true,
		},
		{
			name: "Fields - none match",
			rule: JSONResponseConditions{
				Fields: []string{"user", "post"},
			},
			resp:     createJSONResponse(200, `{"comment":{"id":"1"}}`, t),
			expected: false,
		},
		{
			name: "FieldsAll - all match",
			rule: JSONResponseConditions{
				FieldsAll: []string{"user", "user.id"},
			},
			resp:     createJSONResponse(200, `{"user":{"id":"1","name":"test"}}`, t),
			expected: true,
		},
		{
			name: "FieldsAll - not all match",
			rule: JSONResponseConditions{
				FieldsAll: []string{"user", "post"},
			},
			resp:     createJSONResponse(200, `{"user":{"id":"1"}}`, t),
			expected: false,
		},
		{
			name: "Fields regex matches",
			rule: JSONResponseConditions{
				FieldsRegex: "^user.*",
			},
			resp:     createJSONResponse(200, `{"user":{"id":"1"}}`, t),
			expected: true,
		},

		// Dot notation field matching
		{
			name: "Nested field path matches",
			rule: JSONResponseConditions{
				Fields: []string{"user.id"},
			},
			resp:     createJSONResponse(200, `{"user":{"id":"1","name":"test"}}`, t),
			expected: true,
		},
		{
			name: "Deep nested field path matches",
			rule: JSONResponseConditions{
				Fields: []string{"data.user.profile.email"},
			},
			resp:     createJSONResponse(200, `{"data":{"user":{"profile":{"email":"test@example.com"}}}}`, t),
			expected: true,
		},

		// Field value matching
		{
			name: "Field value matches",
			rule: JSONResponseConditions{
				FieldValue: map[string]string{
					"user.role": "admin",
				},
			},
			resp:     createJSONResponse(200, `{"user":{"role":"admin","id":"1"}}`, t),
			expected: true,
		},
		{
			name: "Field value does not match",
			rule: JSONResponseConditions{
				FieldValue: map[string]string{
					"user.role": "admin",
				},
			},
			resp:     createJSONResponse(200, `{"user":{"role":"user","id":"1"}}`, t),
			expected: false,
		},
		{
			name: "Field value in list - matches",
			rule: JSONResponseConditions{
				FieldValueIn: map[string][]string{
					"user.role": {"admin", "moderator"},
				},
			},
			resp:     createJSONResponse(200, `{"user":{"role":"admin","id":"1"}}`, t),
			expected: true,
		},
		{
			name: "Field value regex matches",
			rule: JSONResponseConditions{
				FieldValueRegex: map[string]string{
					"user.email": ".*@example\\.com",
				},
			},
			resp:     createJSONResponse(200, `{"user":{"email":"test@example.com"}}`, t),
			expected: true,
		},

		// Response contains
		{
			name: "Response contains matches",
			rule: JSONResponseConditions{
				ResponseContains: "user",
			},
			resp:     createJSONResponse(200, `{"user":{"id":"1"}}`, t),
			expected: true,
		},
		{
			name: "Response contains does not match",
			rule: JSONResponseConditions{
				ResponseContains: "user",
			},
			resp:     createJSONResponse(200, `{"post":{"id":"1"}}`, t),
			expected: false,
		},

		// Content-Type checks
		{
			name: "Not JSON - wrong content type",
			rule: JSONResponseConditions{
				ResponseContains: "user",
			},
			resp:     createTextResponse(200, "not json", t),
			expected: false,
		},
		{
			name: "GraphQL content type - matches",
			rule: JSONResponseConditions{
				ResponseContains: "data",
			},
			resp:     createGraphQLContentTypeResponse(200, `{"data":{"user":{"id":"1"}}}`, t),
			expected: true,
		},
		{
			name: "Not JSON - invalid JSON",
			rule: JSONResponseConditions{
				ResponseContains: "user",
			},
			resp:     createJSONResponse(200, `{"invalid": json}`, t),
			expected: false,
		},
		{
			name: "Not JSON - no body",
			rule: JSONResponseConditions{
				ResponseContains: "user",
			},
			resp:     createEmptyResponse(200, t),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rule.match(tt.resp)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestResponseRule_JSON_Match(t *testing.T) {
	tests := []struct {
		name     string
		rule     ResponseRule
		resp     *http.Response
		expected bool
	}{
		{
			name: "JSON rule matches",
			rule: ResponseRule{
				JSON: &JSONResponseConditions{
					ResponseContains: "user",
				},
			},
			resp:     createJSONResponse(200, `{"user":{"id":"1"}}`, t),
			expected: true,
		},
		{
			name: "JSON rule with field value",
			rule: ResponseRule{
				JSON: &JSONResponseConditions{
					FieldValue: map[string]string{
						"user.role": "admin",
					},
				},
			},
			resp:     createJSONResponse(200, `{"user":{"role":"admin"}}`, t),
			expected: true,
		},
		{
			name: "JSON rule with nested fields",
			rule: ResponseRule{
				JSON: &JSONResponseConditions{
					Fields: []string{"user.id"},
				},
			},
			resp:     createJSONResponse(200, `{"user":{"id":"1","name":"test"}}`, t),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rule.Match(tt.resp)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func createGraphQLContentTypeResponse(statusCode int, body string, t *testing.T) *http.Response {
	t.Helper()
	resp := &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}
	resp.Header.Set("Content-Type", "application/graphql")
	return resp
}
