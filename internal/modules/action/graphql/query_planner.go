// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package graphql

import (
	"fmt"
	"strings"
)

// QueryPlan describes how to execute a federated query.
type QueryPlan struct {
	Steps []QueryStep `json:"steps"`
}

// QueryStep represents a single step in the query execution plan.
type QueryStep struct {
	Subgraph  string     `json:"subgraph"`
	Query     string     `json:"query"`
	DependsOn []int      `json:"depends_on,omitempty"` // indices of steps this depends on
	EntityRef *EntityRef `json:"entity_ref,omitempty"` // for _entities queries
}

// EntityRef describes a reference to resolve via the _entities query.
type EntityRef struct {
	TypeName  string   `json:"type_name"`
	KeyFields []string `json:"key_fields"`
}

// Planner creates query plans from incoming GraphQL operations.
type Planner struct {
	subgraphs map[string]*Subgraph
}

// NewPlanner creates a new Planner with the given subgraphs.
func NewPlanner(subgraphs map[string]*Subgraph) *Planner {
	return &Planner{
		subgraphs: subgraphs,
	}
}

// Plan analyzes a GraphQL query and creates an execution plan.
// For the initial implementation, this handles:
//   - Single subgraph queries (route to the right subgraph)
//   - Cross-subgraph entity references (generate _entities queries)
func (p *Planner) Plan(query string, operationName string) (*QueryPlan, error) {
	if query == "" {
		return nil, fmt.Errorf("federation planner: query is required")
	}

	// Identify which root fields are present and which subgraphs own them.
	rootFields := extractRootFields(query)
	if len(rootFields) == 0 {
		return nil, fmt.Errorf("federation planner: no root fields found in query")
	}

	// Map each root field to its owning subgraph.
	fieldSubgraphs := p.resolveFieldSubgraphs(rootFields)

	// Group fields by subgraph.
	subgraphFields := make(map[string][]string)
	var unresolvedFields []string
	for field, sgName := range fieldSubgraphs {
		subgraphFields[sgName] = append(subgraphFields[sgName], field)
	}
	for _, field := range rootFields {
		if _, ok := fieldSubgraphs[field]; !ok {
			unresolvedFields = append(unresolvedFields, field)
		}
	}

	// If no subgraph claims any field, return an error.
	if len(subgraphFields) == 0 && len(unresolvedFields) > 0 {
		return nil, fmt.Errorf("federation planner: no subgraph found for fields: %s", strings.Join(unresolvedFields, ", "))
	}

	// If there are unresolved fields, send them to the first subgraph as a fallback.
	if len(unresolvedFields) > 0 && len(subgraphFields) > 0 {
		// Pick the first subgraph alphabetically for determinism.
		var fallback string
		for sgName := range subgraphFields {
			if fallback == "" || sgName < fallback {
				fallback = sgName
			}
		}
		subgraphFields[fallback] = append(subgraphFields[fallback], unresolvedFields...)
	}

	plan := &QueryPlan{}

	if len(subgraphFields) == 1 {
		// Simple case: all fields belong to one subgraph.
		for sgName := range subgraphFields {
			plan.Steps = append(plan.Steps, QueryStep{
				Subgraph: sgName,
				Query:    query,
			})
		}
		return plan, nil
	}

	// Multi-subgraph case: create a step per subgraph.
	// The primary subgraph (first alphabetically) runs the initial query.
	// Dependent subgraphs run _entities resolution queries.
	stepIndex := 0
	primaryStep := -1

	// Sort subgraph names for deterministic ordering.
	sgNames := sortedKeys(subgraphFields)

	for _, sgName := range sgNames {
		fields := subgraphFields[sgName]

		if primaryStep < 0 {
			// Primary step gets the original query (the subgraph that owns the most fields).
			plan.Steps = append(plan.Steps, QueryStep{
				Subgraph: sgName,
				Query:    query,
			})
			primaryStep = stepIndex
		} else {
			// Build an _entities query for the dependent subgraph.
			entityRef := p.buildEntityRef(sgName, fields)
			entitiesQuery := buildEntitiesQuery(fields)

			plan.Steps = append(plan.Steps, QueryStep{
				Subgraph:  sgName,
				Query:     entitiesQuery,
				DependsOn: []int{primaryStep},
				EntityRef: entityRef,
			})
		}
		stepIndex++
	}

	return plan, nil
}

// resolveFieldSubgraphs maps root field names to the subgraph that owns them.
func (p *Planner) resolveFieldSubgraphs(fields []string) map[string]string {
	result := make(map[string]string)

	for _, field := range fields {
		for sgName, sg := range p.subgraphs {
			// Check if the subgraph has a type that matches this field name.
			// This is a simplified heuristic. In a full implementation, you would
			// inspect the Query type's fields for each subgraph's schema.
			for typeName := range sg.Types {
				if strings.EqualFold(typeName, field) || strings.EqualFold(strings.ToLower(typeName)+"s", strings.ToLower(field)) {
					result[field] = sgName
					break
				}
			}
			if _, ok := result[field]; ok {
				break
			}
		}
	}

	return result
}

// buildEntityRef creates an EntityRef for a subgraph from the fields it should resolve.
func (p *Planner) buildEntityRef(sgName string, fields []string) *EntityRef {
	sg, ok := p.subgraphs[sgName]
	if !ok {
		return nil
	}

	// Find the first federated type in this subgraph that might relate to the fields.
	for _, ft := range sg.Types {
		if len(ft.KeyFields) > 0 {
			return &EntityRef{
				TypeName:  ft.Name,
				KeyFields: ft.KeyFields,
			}
		}
	}

	return nil
}

// buildEntitiesQuery builds a _entities query for resolving cross-subgraph references.
func buildEntitiesQuery(fields []string) string {
	fieldList := strings.Join(fields, "\n    ")
	return fmt.Sprintf(`query {
  _entities(representations: $representations) {
    ... on Entity {
      %s
    }
  }
}`, fieldList)
}

// extractRootFields extracts root-level field names from a GraphQL query string.
// This is a simplified parser that extracts fields from the first selection set.
func extractRootFields(query string) []string {
	var fields []string
	seen := make(map[string]bool)

	// Find the first opening brace (the query/mutation body).
	braceDepth := 0
	parenDepth := 0
	inBody := false
	i := 0

	for i < len(query) {
		ch := query[i]

		if ch == '(' {
			parenDepth++
			i++
			continue
		}
		if ch == ')' {
			if parenDepth > 0 {
				parenDepth--
			}
			i++
			continue
		}

		// Skip everything inside parentheses (arguments).
		if parenDepth > 0 {
			i++
			continue
		}

		if ch == '{' {
			braceDepth++
			if braceDepth == 1 {
				inBody = true
				i++
				continue
			}
		}
		if ch == '}' {
			braceDepth--
			if braceDepth == 0 {
				break
			}
		}

		// At depth 1, we are reading root fields.
		if inBody && braceDepth == 1 {
			// Skip whitespace and non-alpha characters.
			if isAlpha(ch) {
				start := i
				for i < len(query) && isFieldChar(query[i]) {
					i++
				}
				fieldName := query[start:i]
				// Skip GraphQL keywords.
				if !isGraphQLKeyword(fieldName) && !seen[fieldName] {
					fields = append(fields, fieldName)
					seen[fieldName] = true
				}
				continue
			}
		}

		i++
	}

	return fields
}

func isAlpha(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_'
}

func isFieldChar(ch byte) bool {
	return isAlpha(ch) || (ch >= '0' && ch <= '9')
}

func isGraphQLKeyword(s string) bool {
	switch s {
	case "query", "mutation", "subscription", "fragment", "on", "true", "false", "null":
		return true
	}
	return false
}

// sortedKeys returns the keys of a map in sorted order.
func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Simple insertion sort for small slices.
	for i := 1; i < len(keys); i++ {
		j := i
		for j > 0 && keys[j] < keys[j-1] {
			keys[j], keys[j-1] = keys[j-1], keys[j]
			j--
		}
	}
	return keys
}
