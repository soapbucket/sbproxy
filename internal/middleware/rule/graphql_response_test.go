package rule

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

func TestGraphQLResponseConditions_Match(t *testing.T) {
	tests := []struct {
		name     string
		rule     GraphQLResponseConditions
		resp     *http.Response
		expected bool
	}{
		// Has errors
		{
			name: "Has errors - matches",
			rule: GraphQLResponseConditions{
				HasErrors: true,
			},
			resp:     createGraphQLResponse(200, `{"errors":[{"message":"Error occurred"}]}`, t),
			expected: true,
		},
		{
			name: "Has errors - no errors",
			rule: GraphQLResponseConditions{
				HasErrors: true,
			},
			resp:     createGraphQLResponse(200, `{"data":{"user":{"id":"1"}}}`, t),
			expected: false,
		},

		// Error messages
		{
			name: "Error messages - matches",
			rule: GraphQLResponseConditions{
				ErrorMessages: []string{"Error occurred", "Not found"},
			},
			resp:     createGraphQLResponse(200, `{"errors":[{"message":"Error occurred"}]}`, t),
			expected: true,
		},
		{
			name: "Error messages - does not match",
			rule: GraphQLResponseConditions{
				ErrorMessages: []string{"Error occurred"},
			},
			resp:     createGraphQLResponse(200, `{"errors":[{"message":"Different error"}]}`, t),
			expected: false,
		},
		{
			name: "Error messages - no errors",
			rule: GraphQLResponseConditions{
				ErrorMessages: []string{"Error occurred"},
			},
			resp:     createGraphQLResponse(200, `{"data":{"user":{"id":"1"}}}`, t),
			expected: false,
		},

		// Error codes
		{
			name: "Error codes - matches",
			rule: GraphQLResponseConditions{
				ErrorCodes: []string{"NOT_FOUND", "UNAUTHORIZED"},
			},
			resp:     createGraphQLResponse(200, `{"errors":[{"message":"Not found","extensions":{"code":"NOT_FOUND"}}]}`, t),
			expected: true,
		},
		{
			name: "Error codes - does not match",
			rule: GraphQLResponseConditions{
				ErrorCodes: []string{"NOT_FOUND"},
			},
			resp:     createGraphQLResponse(200, `{"errors":[{"message":"Error","extensions":{"code":"UNAUTHORIZED"}}]}`, t),
			expected: false,
		},

		// Error path regex (path is formatted as "[user id]" not "user.id")
		{
			name: "Error path regex - matches",
			rule: GraphQLResponseConditions{
				ErrorPathRegex: `\[user`,
			},
			resp:     createGraphQLResponse(200, `{"errors":[{"message":"Error","path":["user","id"]}]}`, t),
			expected: true,
		},
		{
			name: "Error path regex - does not match",
			rule: GraphQLResponseConditions{
				ErrorPathRegex: `\[user`,
			},
			resp:     createGraphQLResponse(200, `{"errors":[{"message":"Error","path":["post","id"]}]}`, t),
			expected: false,
		},

		// Data fields
		{
			name: "Data fields - any matches",
			rule: GraphQLResponseConditions{
				DataFields: []string{"user", "post"},
			},
			resp:     createGraphQLResponse(200, `{"data":{"user":{"id":"1"}}}`, t),
			expected: true,
		},
		{
			name: "Data fields - none match",
			rule: GraphQLResponseConditions{
				DataFields: []string{"user", "post"},
			},
			resp:     createGraphQLResponse(200, `{"data":{"comment":{"id":"1"}}}`, t),
			expected: false,
		},
		{
			name: "Data fields all - all match",
			rule: GraphQLResponseConditions{
				DataFieldsAll: []string{"user", "id"},
			},
			resp:     createGraphQLResponse(200, `{"data":{"user":{"id":"1","name":"test"}}}`, t),
			expected: true,
		},
		{
			name: "Data fields all - not all match",
			rule: GraphQLResponseConditions{
				DataFieldsAll: []string{"user", "post"},
			},
			resp:     createGraphQLResponse(200, `{"data":{"user":{"id":"1"}}}`, t),
			expected: false,
		},
		{
			name: "Data fields regex - matches",
			rule: GraphQLResponseConditions{
				DataFieldsRegex: "^user.*",
			},
			resp:     createGraphQLResponse(200, `{"data":{"user":{"id":"1"}}}`, t),
			expected: true,
		},
		{
			name: "Data fields regex - does not match",
			rule: GraphQLResponseConditions{
				DataFieldsRegex: "^user.*",
			},
			resp:     createGraphQLResponse(200, `{"data":{"post":{"id":"1"}}}`, t),
			expected: false,
		},
		{
			name: "Data fields - no data",
			rule: GraphQLResponseConditions{
				DataFields: []string{"user"},
			},
			resp:     createGraphQLResponse(200, `{"errors":[{"message":"Error"}]}`, t),
			expected: false,
		},

		// Response contains
		{
			name: "Response contains - matches",
			rule: GraphQLResponseConditions{
				ResponseContains: "user",
			},
			resp:     createGraphQLResponse(200, `{"data":{"user":{"id":"1"}}}`, t),
			expected: true,
		},
		{
			name: "Response contains - does not match",
			rule: GraphQLResponseConditions{
				ResponseContains: "user",
			},
			resp:     createGraphQLResponse(200, `{"data":{"post":{"id":"1"}}}`, t),
			expected: false,
		},

		// Not a GraphQL response
		{
			name: "Not a GraphQL response - wrong content type",
			rule: GraphQLResponseConditions{
				ResponseContains: "user",
			},
			resp:     createTextResponse(200, "not json", t),
			expected: false,
		},
		{
			name: "Not a GraphQL response - invalid JSON",
			rule: GraphQLResponseConditions{
				ResponseContains: "user",
			},
			resp:     createJSONResponse(200, `{"not":"graphql"}`, t),
			expected: false,
		},
		{
			name: "Not a GraphQL response - no body",
			rule: GraphQLResponseConditions{
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

func TestResponseRule_GraphQL_Match(t *testing.T) {
	tests := []struct {
		name     string
		rule     ResponseRule
		resp     *http.Response
		expected bool
	}{
		{
			name: "GraphQL rule matches",
			rule: ResponseRule{
				GraphQL: &GraphQLResponseConditions{
					ResponseContains: "user",
				},
			},
			resp:     createGraphQLResponse(200, `{"data":{"user":{"id":"1"}}}`, t),
			expected: true,
		},
		{
			name: "GraphQL rule does not match",
			rule: ResponseRule{
				GraphQL: &GraphQLResponseConditions{
					ResponseContains: "user",
				},
			},
			resp:     createGraphQLResponse(200, `{"data":{"post":{"id":"1"}}}`, t),
			expected: false,
		},
		{
			name: "GraphQL rule with has errors",
			rule: ResponseRule{
				GraphQL: &GraphQLResponseConditions{
					HasErrors: true,
				},
			},
			resp:     createGraphQLResponse(200, `{"errors":[{"message":"Error"}]}`, t),
			expected: true,
		},
		{
			name: "GraphQL rule with error messages",
			rule: ResponseRule{
				GraphQL: &GraphQLResponseConditions{
					ErrorMessages: []string{"Error occurred"},
				},
			},
			resp:     createGraphQLResponse(200, `{"errors":[{"message":"Error occurred"}]}`, t),
			expected: true,
		},
		{
			name: "GraphQL rule with data fields",
			rule: ResponseRule{
				GraphQL: &GraphQLResponseConditions{
					DataFields: []string{"user"},
				},
			},
			resp:     createGraphQLResponse(200, `{"data":{"user":{"id":"1"}}}`, t),
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

func createGraphQLResponse(statusCode int, body string, t *testing.T) *http.Response {
	t.Helper()
	resp := &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}
	resp.Header.Set("Content-Type", "application/json")
	return resp
}

func createTextResponse(statusCode int, body string, t *testing.T) *http.Response {
	t.Helper()
	resp := &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}
	resp.Header.Set("Content-Type", "text/plain")
	return resp
}

func createJSONResponse(statusCode int, body string, t *testing.T) *http.Response {
	t.Helper()
	resp := &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}
	resp.Header.Set("Content-Type", "application/json")
	return resp
}

func createEmptyResponse(statusCode int, t *testing.T) *http.Response {
	t.Helper()
	resp := &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
		Body:       nil,
	}
	return resp
}

