// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package graphql

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// FederationConfig configures GraphQL Federation v2.
type FederationConfig struct {
	Enabled   bool             `json:"enabled,omitempty"`
	Subgraphs []SubgraphConfig `json:"subgraphs,omitempty"`
}

// SubgraphConfig defines a federated subgraph.
type SubgraphConfig struct {
	Name    string            `json:"name"`
	URL     string            `json:"url"`
	Schema  string            `json:"schema,omitempty"`   // Schema can be provided inline or fetched via introspection
	Headers map[string]string `json:"headers,omitempty"`
}

// FederationRouter routes federated GraphQL queries to subgraphs.
type FederationRouter struct {
	subgraphs map[string]*Subgraph
	mu        sync.RWMutex
	client    *http.Client
}

// Subgraph represents a connected subgraph.
type Subgraph struct {
	Name    string
	URL     string
	Headers map[string]string
	Types   map[string]*FederatedType // typeName -> type info
}

// FederatedType represents a type that participates in federation.
type FederatedType struct {
	Name      string
	KeyFields []string // @key fields
	Subgraph  string   // owning subgraph
}

// NewFederationRouter creates a new FederationRouter from a FederationConfig.
func NewFederationRouter(cfg FederationConfig) (*FederationRouter, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("federation: not enabled")
	}

	if len(cfg.Subgraphs) == 0 {
		return nil, fmt.Errorf("federation: at least one subgraph is required")
	}

	router := &FederationRouter{
		subgraphs: make(map[string]*Subgraph),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	for _, sc := range cfg.Subgraphs {
		if sc.Name == "" {
			return nil, fmt.Errorf("federation: subgraph name is required")
		}
		if sc.URL == "" {
			return nil, fmt.Errorf("federation: subgraph %q url is required", sc.Name)
		}

		sg := &Subgraph{
			Name:    sc.Name,
			URL:     sc.URL,
			Headers: sc.Headers,
			Types:   make(map[string]*FederatedType),
		}

		// Parse schema to extract federated types if provided
		if sc.Schema != "" {
			if err := parseFederatedSchema(sg, sc.Schema); err != nil {
				return nil, fmt.Errorf("federation: subgraph %q schema parse error: %w", sc.Name, err)
			}
		}

		router.subgraphs[sc.Name] = sg
	}

	return router, nil
}

// GetSubgraph returns a subgraph by name.
func (r *FederationRouter) GetSubgraph(name string) (*Subgraph, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	sg, ok := r.subgraphs[name]
	return sg, ok
}

// GetSubgraphs returns all registered subgraphs.
func (r *FederationRouter) GetSubgraphs() map[string]*Subgraph {
	r.mu.RLock()
	defer r.mu.RUnlock()
	// Return a copy
	result := make(map[string]*Subgraph, len(r.subgraphs))
	for k, v := range r.subgraphs {
		result[k] = v
	}
	return result
}

// RegisterType adds a federated type to a subgraph.
func (r *FederationRouter) RegisterType(subgraphName string, ft *FederatedType) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	sg, ok := r.subgraphs[subgraphName]
	if !ok {
		return fmt.Errorf("federation: subgraph %q not found", subgraphName)
	}
	if ft.Name == "" {
		return fmt.Errorf("federation: type name is required")
	}
	ft.Subgraph = subgraphName
	sg.Types[ft.Name] = ft
	return nil
}

// FindTypeOwner returns the subgraph that owns a given federated type.
func (r *FederationRouter) FindTypeOwner(typeName string) (*Subgraph, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, sg := range r.subgraphs {
		if _, ok := sg.Types[typeName]; ok {
			return sg, true
		}
	}
	return nil, false
}

// parseFederatedSchema extracts federated type information from a schema string.
// This is a simplified parser that looks for @key directives in SDL.
func parseFederatedSchema(sg *Subgraph, schema string) error {
	// Parse federation v2 directives from SDL.
	// We look for patterns like: type Product @key(fields: "id") { ... }
	types, err := extractFederatedTypes(schema)
	if err != nil {
		return err
	}
	for _, ft := range types {
		ft.Subgraph = sg.Name
		sg.Types[ft.Name] = ft
	}
	return nil
}

// extractFederatedTypes parses SDL to find types with @key directives.
func extractFederatedTypes(schema string) ([]*FederatedType, error) {
	var types []*FederatedType

	// Simple state machine parser for SDL @key directives.
	// Looks for: type <Name> @key(fields: "<fields>")
	i := 0
	for i < len(schema) {
		// Find "type " keyword
		idx := indexOfToken(schema, i, "type ")
		if idx < 0 {
			break
		}
		i = idx + 5 // skip "type "

		// Extract type name (next whitespace-delimited token)
		nameEnd := i
		for nameEnd < len(schema) && schema[nameEnd] != ' ' && schema[nameEnd] != '{' && schema[nameEnd] != '@' && schema[nameEnd] != '\n' {
			nameEnd++
		}
		if nameEnd == i {
			continue
		}
		typeName := schema[i:nameEnd]
		i = nameEnd

		// Look for @key directive before the opening brace
		braceIdx := indexOfByte(schema, i, '{')
		if braceIdx < 0 {
			break
		}

		segment := schema[i:braceIdx]
		keyFields := extractKeyFields(segment)
		if len(keyFields) > 0 {
			types = append(types, &FederatedType{
				Name:      typeName,
				KeyFields: keyFields,
			})
		}

		i = braceIdx + 1
	}

	return types, nil
}

// extractKeyFields parses @key(fields: "...") directives from a segment of SDL.
func extractKeyFields(segment string) []string {
	var allFields []string
	search := segment
	for {
		keyIdx := indexOfToken(search, 0, "@key(fields:")
		if keyIdx < 0 {
			// Also try with a space: @key(fields: "...")
			keyIdx = indexOfToken(search, 0, "@key(fields: ")
			if keyIdx < 0 {
				break
			}
			keyIdx += len("@key(fields: ")
		} else {
			keyIdx += len("@key(fields:")
		}
		search = search[keyIdx:]

		// Skip whitespace and find opening quote
		j := 0
		for j < len(search) && (search[j] == ' ' || search[j] == '"') {
			j++
		}
		if j >= len(search) {
			break
		}

		// Find closing quote
		end := indexOfByte(search, j, '"')
		if end < 0 {
			break
		}
		fieldsStr := search[j:end]
		// Split on space for compound keys
		for _, f := range splitFields(fieldsStr) {
			if f != "" {
				allFields = append(allFields, f)
			}
		}
		search = search[end+1:]
	}
	return allFields
}

// splitFields splits a space-separated fields string.
func splitFields(s string) []string {
	var fields []string
	current := ""
	for _, c := range s {
		if c == ' ' {
			if current != "" {
				fields = append(fields, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		fields = append(fields, current)
	}
	return fields
}

// indexOfToken finds the index of a token in s starting from pos.
func indexOfToken(s string, pos int, token string) int {
	if pos >= len(s) {
		return -1
	}
	sub := s[pos:]
	for i := 0; i <= len(sub)-len(token); i++ {
		if sub[i:i+len(token)] == token {
			return pos + i
		}
	}
	return -1
}

// indexOfByte finds the index of byte b in s starting from pos.
func indexOfByte(s string, pos int, b byte) int {
	for i := pos; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// MarshalJSON implements json.Marshaler for FederationConfig.
func (fc FederationConfig) MarshalJSON() ([]byte, error) {
	type Alias FederationConfig
	return json.Marshal((*Alias)(&fc))
}
