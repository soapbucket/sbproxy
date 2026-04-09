package config

import (
	"testing"
)

func TestQueryPlannerSingleSubgraph(t *testing.T) {
	subgraphs := map[string]*Subgraph{
		"products": {
			Name: "products",
			URL:  "http://products:4001/graphql",
			Types: map[string]*FederatedType{
				"Product": {Name: "Product", KeyFields: []string{"id"}, Subgraph: "products"},
			},
		},
	}

	planner := NewPlanner(subgraphs)

	query := `query { product(id: "1") { id name price } }`
	plan, err := planner.Plan(query, "")
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	if len(plan.Steps) != 1 {
		t.Fatalf("got %d steps, want 1", len(plan.Steps))
	}

	step := plan.Steps[0]
	if step.Subgraph != "products" {
		t.Errorf("step subgraph = %q, want products", step.Subgraph)
	}
	if step.Query != query {
		t.Errorf("step query = %q, want original query", step.Query)
	}
	if len(step.DependsOn) != 0 {
		t.Errorf("step depends_on = %v, want empty", step.DependsOn)
	}
}

func TestQueryPlannerMultiSubgraph(t *testing.T) {
	subgraphs := map[string]*Subgraph{
		"products": {
			Name: "products",
			URL:  "http://products:4001/graphql",
			Types: map[string]*FederatedType{
				"Product": {Name: "Product", KeyFields: []string{"id"}, Subgraph: "products"},
			},
		},
		"reviews": {
			Name: "reviews",
			URL:  "http://reviews:4002/graphql",
			Types: map[string]*FederatedType{
				"Review": {Name: "Review", KeyFields: []string{"id"}, Subgraph: "reviews"},
			},
		},
	}

	planner := NewPlanner(subgraphs)

	// Query that references both Product and Review types.
	query := `query { Product { id name } Review { id body } }`
	plan, err := planner.Plan(query, "")
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	if len(plan.Steps) != 2 {
		t.Fatalf("got %d steps, want 2", len(plan.Steps))
	}

	// First step should have no dependencies.
	if len(plan.Steps[0].DependsOn) != 0 {
		t.Errorf("first step should have no dependencies, got %v", plan.Steps[0].DependsOn)
	}

	// Second step should depend on the first.
	if len(plan.Steps[1].DependsOn) != 1 || plan.Steps[1].DependsOn[0] != 0 {
		t.Errorf("second step depends_on = %v, want [0]", plan.Steps[1].DependsOn)
	}
}

func TestQueryPlannerEmptyQuery(t *testing.T) {
	planner := NewPlanner(map[string]*Subgraph{})

	_, err := planner.Plan("", "")
	if err == nil {
		t.Error("Plan() should fail with empty query")
	}
}

func TestQueryPlannerNoMatchingSubgraph(t *testing.T) {
	subgraphs := map[string]*Subgraph{
		"products": {
			Name:  "products",
			URL:   "http://products:4001/graphql",
			Types: map[string]*FederatedType{},
		},
	}

	planner := NewPlanner(subgraphs)

	// Query with fields that do not match any type.
	query := `query { unknownField { id } }`
	_, err := planner.Plan(query, "")
	if err == nil {
		t.Error("Plan() should fail when no subgraph matches any field")
	}
}

func TestExtractRootFields(t *testing.T) {
	tests := []struct {
		name   string
		query  string
		expect []string
	}{
		{
			name:   "simple query",
			query:  `query { products { id name } }`,
			expect: []string{"products"},
		},
		{
			name:   "multiple root fields",
			query:  `query { products { id } reviews { body } }`,
			expect: []string{"products", "reviews"},
		},
		{
			name:   "mutation",
			query:  `mutation { createProduct(name: "Test") { id } }`,
			expect: []string{"createProduct"},
		},
		{
			name:   "shorthand query",
			query:  `{ product(id: "1") { id name } }`,
			expect: []string{"product"},
		},
		{
			name:   "named query",
			query:  `query GetProducts { products { id name price } }`,
			expect: []string{"products"},
		},
		{
			name:   "empty braces",
			query:  `query { }`,
			expect: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields := extractRootFields(tt.query)
			if len(fields) != len(tt.expect) {
				t.Errorf("got %d fields %v, want %d fields %v", len(fields), fields, len(tt.expect), tt.expect)
				return
			}
			for i, f := range tt.expect {
				if fields[i] != f {
					t.Errorf("field %d = %q, want %q", i, fields[i], f)
				}
			}
		})
	}
}

func TestQueryPlanStepDependencies(t *testing.T) {
	subgraphs := map[string]*Subgraph{
		"alpha": {
			Name: "alpha",
			URL:  "http://alpha:4001/graphql",
			Types: map[string]*FederatedType{
				"Alpha": {Name: "Alpha", KeyFields: []string{"id"}, Subgraph: "alpha"},
			},
		},
		"beta": {
			Name: "beta",
			URL:  "http://beta:4002/graphql",
			Types: map[string]*FederatedType{
				"Beta": {Name: "Beta", KeyFields: []string{"id"}, Subgraph: "beta"},
			},
		},
	}

	planner := NewPlanner(subgraphs)
	query := `query { Alpha { id } Beta { id } }`
	plan, err := planner.Plan(query, "TestOp")
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	// Verify the plan has exactly 2 steps.
	if len(plan.Steps) != 2 {
		t.Fatalf("got %d steps, want 2", len(plan.Steps))
	}

	// The first step (alphabetically "alpha") should have no dependencies.
	if plan.Steps[0].Subgraph != "alpha" {
		t.Errorf("first step subgraph = %q, want alpha", plan.Steps[0].Subgraph)
	}
	if len(plan.Steps[0].DependsOn) != 0 {
		t.Errorf("first step should have no dependencies")
	}

	// The second step should depend on step 0.
	if plan.Steps[1].Subgraph != "beta" {
		t.Errorf("second step subgraph = %q, want beta", plan.Steps[1].Subgraph)
	}
	if len(plan.Steps[1].DependsOn) != 1 || plan.Steps[1].DependsOn[0] != 0 {
		t.Errorf("second step depends_on = %v, want [0]", plan.Steps[1].DependsOn)
	}

	// Second step should have an entity ref.
	if plan.Steps[1].EntityRef == nil {
		t.Error("second step should have an entity ref")
	} else if plan.Steps[1].EntityRef.TypeName != "Beta" {
		t.Errorf("entity ref type = %q, want Beta", plan.Steps[1].EntityRef.TypeName)
	}
}

func TestSortedKeys(t *testing.T) {
	m := map[string][]string{
		"charlie": {"c"},
		"alpha":   {"a"},
		"bravo":   {"b"},
	}
	keys := sortedKeys(m)
	expected := []string{"alpha", "bravo", "charlie"}
	if len(keys) != len(expected) {
		t.Fatalf("got %d keys, want %d", len(keys), len(expected))
	}
	for i, k := range expected {
		if keys[i] != k {
			t.Errorf("key %d = %q, want %q", i, keys[i], k)
		}
	}
}
