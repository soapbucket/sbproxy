package rule

import (
	"bytes"
	"net/http"
	"testing"
)

func TestJSONConditions_Match(t *testing.T) {
	tests := []struct {
		name     string
		rule     JSONConditions
		req      *http.Request
		expected bool
	}{
		// Field matching
		{
			name: "Fields - any matches",
			rule: JSONConditions{
				Fields: []string{"user", "post"},
			},
			req:      createJSONRequest("POST", `{"user":{"id":"1"}}`, t),
			expected: true,
		},
		{
			name: "Fields - none match",
			rule: JSONConditions{
				Fields: []string{"user", "post"},
			},
			req:      createJSONRequest("POST", `{"comment":{"id":"1"}}`, t),
			expected: false,
		},
		{
			name: "FieldsAll - all match",
			rule: JSONConditions{
				FieldsAll: []string{"user", "user.id"},
			},
			req:      createJSONRequest("POST", `{"user":{"id":"1","name":"test"}}`, t),
			expected: true,
		},
		{
			name: "FieldsAll - not all match",
			rule: JSONConditions{
				FieldsAll: []string{"user", "post"},
			},
			req:      createJSONRequest("POST", `{"user":{"id":"1"}}`, t),
			expected: false,
		},
		{
			name: "Fields regex matches",
			rule: JSONConditions{
				FieldsRegex: "^user.*",
			},
			req:      createJSONRequest("POST", `{"user":{"id":"1"}}`, t),
			expected: true,
		},
		{
			name: "Fields regex does not match",
			rule: JSONConditions{
				FieldsRegex: "^user.*",
			},
			req:      createJSONRequest("POST", `{"post":{"id":"1"}}`, t),
			expected: false,
		},

		// Dot notation field matching
		{
			name: "Nested field path matches",
			rule: JSONConditions{
				Fields: []string{"user.id"},
			},
			req:      createJSONRequest("POST", `{"user":{"id":"1","name":"test"}}`, t),
			expected: true,
		},
		{
			name: "Deep nested field path matches",
			rule: JSONConditions{
				Fields: []string{"data.user.profile.email"},
			},
			req:      createJSONRequest("POST", `{"data":{"user":{"profile":{"email":"test@example.com"}}}}`, t),
			expected: true,
		},

		// Field value matching
		{
			name: "Field value matches",
			rule: JSONConditions{
				FieldValue: map[string]string{
					"user.role": "admin",
				},
			},
			req:      createJSONRequest("POST", `{"user":{"role":"admin","id":"1"}}`, t),
			expected: true,
		},
		{
			name: "Field value does not match",
			rule: JSONConditions{
				FieldValue: map[string]string{
					"user.role": "admin",
				},
			},
			req:      createJSONRequest("POST", `{"user":{"role":"user","id":"1"}}`, t),
			expected: false,
		},
		{
			name: "Field value in list - matches",
			rule: JSONConditions{
				FieldValueIn: map[string][]string{
					"user.role": {"admin", "moderator"},
				},
			},
			req:      createJSONRequest("POST", `{"user":{"role":"admin","id":"1"}}`, t),
			expected: true,
		},
		{
			name: "Field value in list - does not match",
			rule: JSONConditions{
				FieldValueIn: map[string][]string{
					"user.role": {"admin", "moderator"},
				},
			},
			req:      createJSONRequest("POST", `{"user":{"role":"user","id":"1"}}`, t),
			expected: false,
		},
		{
			name: "Field value regex matches",
			rule: JSONConditions{
				FieldValueRegex: map[string]string{
					"user.email": ".*@example\\.com",
				},
			},
			req:      createJSONRequest("POST", `{"user":{"email":"test@example.com"}}`, t),
			expected: true,
		},
		{
			name: "Field value regex does not match",
			rule: JSONConditions{
				FieldValueRegex: map[string]string{
					"user.email": ".*@example\\.com",
				},
			},
			req:      createJSONRequest("POST", `{"user":{"email":"test@other.com"}}`, t),
			expected: false,
		},

		// Body contains
		{
			name: "Body contains matches",
			rule: JSONConditions{
				BodyContains: "user",
			},
			req:      createJSONRequest("POST", `{"user":{"id":"1"}}`, t),
			expected: true,
		},
		{
			name: "Body contains does not match",
			rule: JSONConditions{
				BodyContains: "user",
			},
			req:      createJSONRequest("POST", `{"post":{"id":"1"}}`, t),
			expected: false,
		},

		// Content-Type checks
		{
			name: "Not JSON - wrong content type",
			rule: JSONConditions{
				BodyContains: "user",
			},
			req:      createTextRequest("POST", "not json", t),
			expected: false,
		},
		{
			name: "GraphQL content type - matches",
			rule: JSONConditions{
				BodyContains: "query",
			},
			req:      createGraphQLContentTypeRequest("POST", `{"query":"query { user { id } }"}`, t),
			expected: true,
		},
		{
			name: "Not JSON - invalid JSON",
			rule: JSONConditions{
				BodyContains: "user",
			},
			req:      createJSONRequest("POST", `{"invalid": json}`, t),
			expected: false,
		},
		{
			name: "Not JSON - no body",
			rule: JSONConditions{
				BodyContains: "user",
			},
			req:      createEmptyBodyRequest("POST", t),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rule.match(tt.req)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestRequestRule_JSON_Match(t *testing.T) {
	tests := []struct {
		name     string
		rule     RequestRule
		req      *http.Request
		expected bool
	}{
		{
			name: "JSON rule matches",
			rule: RequestRule{
				JSON: &JSONConditions{
					BodyContains: "user",
				},
			},
			req:      createJSONRequest("POST", `{"user":{"id":"1"}}`, t),
			expected: true,
		},
		{
			name: "JSON rule with field value",
			rule: RequestRule{
				JSON: &JSONConditions{
					FieldValue: map[string]string{
						"user.role": "admin",
					},
				},
			},
			req:      createJSONRequest("POST", `{"user":{"role":"admin"}}`, t),
			expected: true,
		},
		{
			name: "JSON rule with nested fields",
			rule: RequestRule{
				JSON: &JSONConditions{
					Fields: []string{"user.id"},
				},
			},
			req:      createJSONRequest("POST", `{"user":{"id":"1","name":"test"}}`, t),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rule.Match(tt.req)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func createGraphQLContentTypeRequest(method, body string, t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, "http://example.com/graphql", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/graphql")
	return req
}

func createEmptyBodyRequest(method string, t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, "http://example.com/api", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}

