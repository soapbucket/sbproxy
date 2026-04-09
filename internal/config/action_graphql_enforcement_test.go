package config

import (
	"testing"
)

// helper to create a GraphQLAction with custom limits for testing
func newTestGraphQLAction(t *testing.T, maxDepth, maxComplexity, maxAliases int) *GraphQLAction {
	t.Helper()
	data := []byte(`{
		"type": "graphql",
		"url": "http://example.com/graphql"
	}`)
	action, err := NewGraphQLAction(data)
	if err != nil {
		t.Fatalf("Failed to create GraphQL action: %v", err)
	}
	gql := action.(*GraphQLAction)
	if maxDepth > 0 {
		gql.MaxDepth = maxDepth
	}
	if maxComplexity > 0 {
		gql.MaxComplexity = maxComplexity
	}
	if maxAliases > 0 {
		gql.MaxAliases = maxAliases
	}
	return gql
}

func TestGraphQLEnforcement_DefaultMaxAliases(t *testing.T) {
	data := []byte(`{
		"type": "graphql",
		"url": "http://example.com/graphql"
	}`)
	action, err := NewGraphQLAction(data)
	if err != nil {
		t.Fatalf("Failed to create GraphQL action: %v", err)
	}
	gql := action.(*GraphQLAction)
	if gql.MaxAliases != DefaultGraphQLMaxAliases {
		t.Errorf("Expected default MaxAliases %d, got %d", DefaultGraphQLMaxAliases, gql.MaxAliases)
	}
}

func TestGraphQLEnforcement_CustomMaxAliases(t *testing.T) {
	data := []byte(`{
		"type": "graphql",
		"url": "http://example.com/graphql",
		"max_aliases": 5
	}`)
	action, err := NewGraphQLAction(data)
	if err != nil {
		t.Fatalf("Failed to create GraphQL action: %v", err)
	}
	gql := action.(*GraphQLAction)
	if gql.MaxAliases != 5 {
		t.Errorf("Expected MaxAliases 5, got %d", gql.MaxAliases)
	}
}

func TestGraphQLEnforcement_CalculateAliases(t *testing.T) {
	gql := newTestGraphQLAction(t, 0, 0, 0)

	tests := []struct {
		name     string
		query    string
		expected int
	}{
		{
			name:     "no aliases",
			query:    `{ user { id name } }`,
			expected: 0,
		},
		{
			name:     "single alias",
			query:    `{ myUser: user { id name } }`,
			expected: 1,
		},
		{
			name:     "multiple aliases at same level",
			query:    `{ a: user { id } b: user { name } c: user { email } }`,
			expected: 3,
		},
		{
			name:     "nested aliases",
			query:    `{ myUser: user { myName: name myEmail: email } }`,
			expected: 3,
		},
		{
			name:     "mixed aliased and non-aliased",
			query:    `{ myUser: user { id name } posts { id title } }`,
			expected: 1,
		},
		{
			name:     "alias amplification attack",
			query:    `{ a0: user { id } a1: user { id } a2: user { id } a3: user { id } a4: user { id } a5: user { id } a6: user { id } a7: user { id } a8: user { id } a9: user { id } a10: user { id } a11: user { id } }`,
			expected: 12,
		},
		{
			name:     "inline fragment with alias",
			query:    `{ ... on User { myName: name } }`,
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := gql.parseQuery(tt.query)
			if err != nil {
				t.Fatalf("Failed to parse query: %v", err)
			}
			aliases := gql.calculateAliases(doc)
			if aliases != tt.expected {
				t.Errorf("Expected %d aliases, got %d", tt.expected, aliases)
			}
		})
	}
}

func TestGraphQLEnforcement_CalculateDepth(t *testing.T) {
	gql := newTestGraphQLAction(t, 0, 0, 0)

	tests := []struct {
		name     string
		query    string
		expected int
	}{
		{
			name:     "flat query",
			query:    `{ user { id name } }`,
			expected: 2,
		},
		{
			name:     "deeply nested query",
			query:    `{ user { posts { comments { author { name } } } } }`,
			expected: 5,
		},
		{
			name:     "single field",
			query:    `{ __typename }`,
			expected: 1,
		},
		{
			name:     "multiple top-level fields",
			query:    `{ user { id } posts { title } }`,
			expected: 2,
		},
		{
			name:     "uneven nesting picks deepest",
			query:    `{ user { id } posts { comments { text } } }`,
			expected: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := gql.parseQuery(tt.query)
			if err != nil {
				t.Fatalf("Failed to parse query: %v", err)
			}
			depth := gql.calculateDepth(doc)
			if depth != tt.expected {
				t.Errorf("Expected depth %d, got %d", tt.expected, depth)
			}
		})
	}
}

func TestGraphQLEnforcement_CalculateComplexity(t *testing.T) {
	gql := newTestGraphQLAction(t, 0, 0, 0)

	tests := []struct {
		name         string
		query        string
		minExpected  int // complexity is at least this
	}{
		{
			name:        "single field",
			query:       `{ __typename }`,
			minExpected: 1,
		},
		{
			name:        "nested fields increase complexity",
			query:       `{ user { id name email } }`,
			minExpected: 3,
		},
		{
			name:        "deeply nested increases complexity more",
			query:       `{ user { posts { comments { author { name } } } } }`,
			minExpected: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := gql.parseQuery(tt.query)
			if err != nil {
				t.Fatalf("Failed to parse query: %v", err)
			}
			complexity := gql.calculateComplexity(doc)
			if complexity < tt.minExpected {
				t.Errorf("Expected complexity >= %d, got %d", tt.minExpected, complexity)
			}
		})
	}
}

func TestGraphQLEnforcement_DepthExceedsLimit(t *testing.T) {
	gql := newTestGraphQLAction(t, 2, 0, 0)

	// Depth 2 should pass
	doc, err := gql.parseQuery(`{ user { id } }`)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	depth := gql.calculateDepth(doc)
	if depth > gql.MaxDepth {
		t.Errorf("Depth %d should not exceed max %d for simple query", depth, gql.MaxDepth)
	}

	// Depth 3 should exceed the limit of 2
	doc, err = gql.parseQuery(`{ user { posts { id } } }`)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	depth = gql.calculateDepth(doc)
	if depth <= gql.MaxDepth {
		t.Errorf("Depth %d should exceed max %d for nested query", depth, gql.MaxDepth)
	}
}

func TestGraphQLEnforcement_AliasesExceedLimit(t *testing.T) {
	gql := newTestGraphQLAction(t, 0, 0, 2)

	// 1 alias should pass
	doc, err := gql.parseQuery(`{ myUser: user { id } }`)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	aliases := gql.calculateAliases(doc)
	if aliases > gql.MaxAliases {
		t.Errorf("Aliases %d should not exceed max %d", aliases, gql.MaxAliases)
	}

	// 3 aliases should exceed the limit of 2
	doc, err = gql.parseQuery(`{ a: user { id } b: user { id } c: user { id } }`)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	aliases = gql.calculateAliases(doc)
	if aliases <= gql.MaxAliases {
		t.Errorf("Aliases %d should exceed max %d", aliases, gql.MaxAliases)
	}
}

func TestGraphQLEnforcement_ValidQueryPassesAllChecks(t *testing.T) {
	gql := newTestGraphQLAction(t, 10, 100, 10)

	query := `{
		user {
			id
			name
			email
			posts {
				id
				title
			}
		}
	}`

	doc, err := gql.parseQuery(query)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	depth := gql.calculateDepth(doc)
	if depth > gql.MaxDepth {
		t.Errorf("Depth %d exceeds limit %d for valid query", depth, gql.MaxDepth)
	}

	complexity := gql.calculateComplexity(doc)
	if complexity > gql.MaxComplexity {
		t.Errorf("Complexity %d exceeds limit %d for valid query", complexity, gql.MaxComplexity)
	}

	aliases := gql.calculateAliases(doc)
	if aliases > gql.MaxAliases {
		t.Errorf("Aliases %d exceeds limit %d for valid query", aliases, gql.MaxAliases)
	}

	cost := gql.calculateCost(doc)
	if cost > gql.MaxCost {
		t.Errorf("Cost %d exceeds limit %d for valid query", cost, gql.MaxCost)
	}
}
