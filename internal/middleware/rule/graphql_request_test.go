package rule

import (
	"bytes"
	"net/http"
	"net/url"
	"testing"
)

func TestGraphQLConditions_Match(t *testing.T) {
	tests := []struct {
		name     string
		rule     GraphQLConditions
		req      *http.Request
		expected bool
	}{
		// Operation name matching
		{
			name: "Operation name matches",
			rule: GraphQLConditions{
				OperationName: "GetUser",
			},
			req:      createGraphQLRequest("POST", `{"query":"query GetUser { user { id name } }","operationName":"GetUser"}`, t),
			expected: true,
		},
		{
			name: "Operation name does not match",
			rule: GraphQLConditions{
				OperationName: "GetUser",
			},
			req:      createGraphQLRequest("POST", `{"query":"query GetPost { post { id title } }","operationName":"GetPost"}`, t),
			expected: false,
		},
		{
			name: "Operation names - one matches",
			rule: GraphQLConditions{
				OperationNames: []string{"GetUser", "GetPost"},
			},
			req:      createGraphQLRequest("POST", `{"query":"query GetUser { user { id } }","operationName":"GetUser"}`, t),
			expected: true,
		},
		{
			name: "Operation names - none match",
			rule: GraphQLConditions{
				OperationNames: []string{"GetUser", "GetPost"},
			},
			req:      createGraphQLRequest("POST", `{"query":"query GetComment { comment { id } }","operationName":"GetComment"}`, t),
			expected: false,
		},
		{
			name: "Operation name regex matches",
			rule: GraphQLConditions{
				OperationNameRegex: "^Get.*",
			},
			req:      createGraphQLRequest("POST", `{"query":"query GetUser { user { id } }","operationName":"GetUser"}`, t),
			expected: true,
		},
		{
			name: "Operation name regex does not match",
			rule: GraphQLConditions{
				OperationNameRegex: "^Get.*",
			},
			req:      createGraphQLRequest("POST", `{"query":"query CreateUser { createUser { id } }","operationName":"CreateUser"}`, t),
			expected: false,
		},

		// Operation type matching
		{
			name: "Operation type query matches",
			rule: GraphQLConditions{
				OperationTypes: []string{"query"},
			},
			req:      createGraphQLRequest("POST", `{"query":"query { user { id name } }"}`, t),
			expected: true,
		},
		{
			name: "Operation type mutation matches",
			rule: GraphQLConditions{
				OperationTypes: []string{"mutation"},
			},
			req:      createGraphQLRequest("POST", `{"query":"mutation { createUser(name: \"test\") { id } }"}`, t),
			expected: true,
		},
		{
			name: "Operation type does not match",
			rule: GraphQLConditions{
				OperationTypes: []string{"mutation"},
			},
			req:      createGraphQLRequest("POST", `{"query":"query { user { id } }"}`, t),
			expected: false,
		},
		{
			name: "Operation types - one matches",
			rule: GraphQLConditions{
				OperationTypes: []string{"query", "mutation"},
			},
			req:      createGraphQLRequest("POST", `{"query":"mutation { createUser { id } }"}`, t),
			expected: true,
		},

		// Field matching
		{
			name: "Fields - any matches",
			rule: GraphQLConditions{
				Fields: []string{"user", "post"},
			},
			req:      createGraphQLRequest("POST", `{"query":"query { user { id name } }"}`, t),
			expected: true,
		},
		{
			name: "Fields - none match",
			rule: GraphQLConditions{
				Fields: []string{"user", "post"},
			},
			req:      createGraphQLRequest("POST", `{"query":"query { comment { id } }"}`, t),
			expected: false,
		},
		{
			name: "FieldsAll - all match",
			rule: GraphQLConditions{
				FieldsAll: []string{"user", "id"},
			},
			req:      createGraphQLRequest("POST", `{"query":"query { user { id name } }"}`, t),
			expected: true,
		},
		{
			name: "FieldsAll - not all match",
			rule: GraphQLConditions{
				FieldsAll: []string{"user", "post"},
			},
			req:      createGraphQLRequest("POST", `{"query":"query { user { id } }"}`, t),
			expected: false,
		},
		{
			name: "Fields regex matches",
			rule: GraphQLConditions{
				FieldsRegex: "^user.*",
			},
			req:      createGraphQLRequest("POST", `{"query":"query { user { id } }"}`, t),
			expected: true,
		},
		{
			name: "Fields regex does not match",
			rule: GraphQLConditions{
				FieldsRegex: "^user.*",
			},
			req:      createGraphQLRequest("POST", `{"query":"query { post { id } }"}`, t),
			expected: false,
		},

		// Query contains
		{
			name: "Query contains matches",
			rule: GraphQLConditions{
				QueryContains: "user",
			},
			req:      createGraphQLRequest("POST", `{"query":"query { user { id name } }"}`, t),
			expected: true,
		},
		{
			name: "Query contains does not match",
			rule: GraphQLConditions{
				QueryContains: "user",
			},
			req:      createGraphQLRequest("POST", `{"query":"query { post { id } }"}`, t),
			expected: false,
		},

		// GET request
		{
			name: "GET request with query parameter",
			rule: GraphQLConditions{
				QueryContains: "user",
			},
			req:      createGraphQLGetRequest("query { user { id } }", "", t),
			expected: true,
		},
		{
			name: "GET request with operation name",
			rule: GraphQLConditions{
				OperationName: "GetUser",
			},
			req:      createGraphQLGetRequest("query GetUser { user { id } }", "GetUser", t),
			expected: true,
		},

		// Not a GraphQL request
		{
			name: "Not a GraphQL request - no query",
			rule: GraphQLConditions{
				QueryContains: "user",
			},
			req:      createJSONRequest("POST", `{"data":"test"}`, t),
			expected: false,
		},
		{
			name: "Not a GraphQL request - wrong content type",
			rule: GraphQLConditions{
				QueryContains: "user",
			},
			req:      createTextRequest("POST", "not json", t),
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

func createGraphQLRequest(method, body string, t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, "http://example.com/graphql", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}

func createGraphQLGetRequest(query, operationName string, t *testing.T) *http.Request {
	t.Helper()
	u, err := url.Parse("http://example.com/graphql")
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("query", query)
	if operationName != "" {
		q.Set("operationName", operationName)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// GraphQL GET requests need Content-Type header for the match function
	req.Header.Set("Content-Type", "application/json")
	return req
}

func createJSONRequest(method, body string, t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, "http://example.com/api", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}

func createTextRequest(method, body string, t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, "http://example.com/api", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "text/plain")
	return req
}

func TestRequestRule_GraphQL_Match(t *testing.T) {
	tests := []struct {
		name     string
		rule     RequestRule
		req      *http.Request
		expected bool
	}{
		{
			name: "GraphQL rule matches",
			rule: RequestRule{
				GraphQL: &GraphQLConditions{
					QueryContains: "user",
				},
			},
			req:      createGraphQLRequest("POST", `{"query":"query { user { id } }"}`, t),
			expected: true,
		},
		{
			name: "GraphQL rule does not match",
			rule: RequestRule{
				GraphQL: &GraphQLConditions{
					QueryContains: "user",
				},
			},
			req:      createGraphQLRequest("POST", `{"query":"query { post { id } }"}`, t),
			expected: false,
		},
		{
			name: "GraphQL rule with operation name",
			rule: RequestRule{
				GraphQL: &GraphQLConditions{
					OperationName: "GetUser",
				},
			},
			req:      createGraphQLRequest("POST", `{"query":"query GetUser { user { id } }","operationName":"GetUser"}`, t),
			expected: true,
		},
		{
			name: "GraphQL rule with operation type",
			rule: RequestRule{
				GraphQL: &GraphQLConditions{
					OperationTypes: []string{"mutation"},
				},
			},
			req:      createGraphQLRequest("POST", `{"query":"mutation { createUser { id } }"}`, t),
			expected: true,
		},
		{
			name: "GraphQL rule with fields",
			rule: RequestRule{
				GraphQL: &GraphQLConditions{
					Fields: []string{"user"},
				},
			},
			req:      createGraphQLRequest("POST", `{"query":"query { user { id name } }"}`, t),
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
