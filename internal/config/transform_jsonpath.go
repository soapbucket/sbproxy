// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// JSONPathTransformConfig configures JSON path transformation
type JSONPathTransformConfig struct {
	Operations []JSONPathOperation `json:"operations"`
}

// JSONPathOperationType defines the type of operation
type JSONPathOperationType string

const (
	// JSONPathExtract is a constant for json path extract.
	JSONPathExtract JSONPathOperationType = "extract"
	// JSONPathSet is a constant for json path set.
	JSONPathSet     JSONPathOperationType = "set"
	// JSONPathDelete is a constant for json path delete.
	JSONPathDelete  JSONPathOperationType = "delete"
	// JSONPathCopy is a constant for json path copy.
	JSONPathCopy    JSONPathOperationType = "copy"
)

// JSONPathOperation represents a single JSON path operation
type JSONPathOperation struct {
	Type   JSONPathOperationType `json:"type"`
	Path   string                `json:"path"`   // JSON path to operate on
	Value  interface{}           `json:"value,omitempty"`  // Value to set (for "set" type)
	Target string                `json:"target,omitempty"` // Target path or header (for "extract" or "copy")
}

// NewJSONPathTransform creates a JSON path transform
func NewJSONPathTransform(operations []JSONPathOperation) *JSONPathTransformConfig {
	return &JSONPathTransformConfig{
		Operations: operations,
	}
}

// Transform applies JSON path operations to the response body
func (t *JSONPathTransformConfig) Transform(body []byte) ([]byte, error) {
	// Parse JSON
	if !gjson.ValidBytes(body) {
		return nil, fmt.Errorf("invalid JSON")
	}

	jsonStr := string(body)
	var err error

	// Apply each operation in order
	for i, op := range t.Operations {
		slog.Debug("applying JSON path operation",
			"operation", i+1,
			"type", op.Type,
			"path", op.Path)

		switch op.Type {
		case JSONPathExtract:
			// Extract is handled at the handler level to set headers
			// We just validate the path exists
			result := gjson.Get(jsonStr, op.Path)
			if !result.Exists() {
				slog.Debug("JSON path not found for extract",
					"path", op.Path)
			}

		case JSONPathSet:
			// Set a value at the given path
			jsonStr, err = sjson.Set(jsonStr, op.Path, op.Value)
			if err != nil {
				return nil, fmt.Errorf("failed to set path %q: %w", op.Path, err)
			}

		case JSONPathDelete:
			// Delete a value at the given path
			jsonStr, err = sjson.Delete(jsonStr, op.Path)
			if err != nil {
				return nil, fmt.Errorf("failed to delete path %q: %w", op.Path, err)
			}

		case JSONPathCopy:
			// Copy value from one path to another
			if op.Target == "" {
				return nil, fmt.Errorf("target path required for copy operation")
			}
			
			result := gjson.Get(jsonStr, op.Path)
			if !result.Exists() {
				slog.Debug("source path not found for copy",
					"source", op.Path,
					"target", op.Target)
				continue
			}

			jsonStr, err = sjson.Set(jsonStr, op.Target, result.Value())
			if err != nil {
				return nil, fmt.Errorf("failed to copy from %q to %q: %w", op.Path, op.Target, err)
			}

		default:
			return nil, fmt.Errorf("unknown operation type: %s", op.Type)
		}
	}

	return []byte(jsonStr), nil
}

// ExtractToHeaders extracts values from JSON and returns them as header key-value pairs
func (t *JSONPathTransformConfig) ExtractToHeaders(body []byte) map[string]string {
	headers := make(map[string]string)

	if !gjson.ValidBytes(body) {
		slog.Debug("invalid JSON for header extraction")
		return headers
	}

	jsonStr := string(body)

	for _, op := range t.Operations {
		if op.Type == JSONPathExtract && op.Target != "" {
			result := gjson.Get(jsonStr, op.Path)
			if result.Exists() {
				// Convert value to string
				var value string
				switch result.Type {
				case gjson.String:
					value = result.String()
				case gjson.Number:
					value = result.Raw
				case gjson.True:
					value = "true"
				case gjson.False:
					value = "false"
				case gjson.JSON:
					value = result.Raw
				default:
					value = result.String()
				}
				
				headers[op.Target] = value
				slog.Debug("extracted JSON value to header",
					"path", op.Path,
					"header", op.Target,
					"value", value)
			}
		}
	}

	return headers
}

// JSONPathQuery represents a compiled JSON path query
type JSONPathQuery struct {
	path string
}

// JSONPathCache provides caching for JSON path queries
type JSONPathCache struct {
	mu      sync.RWMutex
	queries map[string]*JSONPathQuery
	maxSize int
}

// NewJSONPathCache creates a new JSON path cache
func NewJSONPathCache(maxSize int) *JSONPathCache {
	if maxSize <= 0 {
		maxSize = 1000
	}
	
	return &JSONPathCache{
		queries: make(map[string]*JSONPathQuery),
		maxSize: maxSize,
	}
}

// Get retrieves a value from the cache
func (c *JSONPathCache) Get(json, path string) (gjson.Result, bool) {
	c.mu.RLock()
	query, exists := c.queries[path]
	c.mu.RUnlock()

	if !exists {
		return gjson.Result{}, false
	}

	// Execute query (gjson is already very fast)
	return gjson.Get(json, query.path), true
}

// Set stores a query in the cache
func (c *JSONPathCache) Set(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check size limit
	if len(c.queries) >= c.maxSize {
		// Simple eviction: clear half the cache
		for k := range c.queries {
			delete(c.queries, k)
			if len(c.queries) <= c.maxSize/2 {
				break
			}
		}
	}

	c.queries[path] = &JSONPathQuery{path: path}
}

// Clear clears the cache
func (c *JSONPathCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.queries = make(map[string]*JSONPathQuery)
}

// Size returns the number of cached queries
func (c *JSONPathCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.queries)
}

// ValidateJSONPath validates a JSON path expression
func ValidateJSONPath(path string) error {
	if path == "" {
		return fmt.Errorf("empty JSON path")
	}

	// Basic validation - gjson paths should start with $ or be valid field names
	if !strings.HasPrefix(path, "$") && !strings.HasPrefix(path, "@") {
		// Check if it's a simple field name
		if strings.ContainsAny(path, " \t\n") {
			return fmt.Errorf("invalid JSON path: contains whitespace")
		}
	}

	return nil
}

// ParseJSONPathOperations parses and validates JSON path operations
func ParseJSONPathOperations(data []byte) ([]JSONPathOperation, error) {
	var ops []JSONPathOperation
	if err := json.Unmarshal(data, &ops); err != nil {
		return nil, fmt.Errorf("failed to parse operations: %w", err)
	}

	// Validate operations
	for i, op := range ops {
		if err := ValidateJSONPath(op.Path); err != nil {
			return nil, fmt.Errorf("invalid path in operation %d: %w", i, err)
		}

		switch op.Type {
		case JSONPathExtract:
			if op.Target == "" {
				return nil, fmt.Errorf("operation %d: extract requires target", i)
			}
		case JSONPathSet:
			if op.Value == nil {
				return nil, fmt.Errorf("operation %d: set requires value", i)
			}
		case JSONPathDelete:
			// No additional validation needed
		case JSONPathCopy:
			if op.Target == "" {
				return nil, fmt.Errorf("operation %d: copy requires target", i)
			}
		default:
			return nil, fmt.Errorf("operation %d: unknown type %q", i, op.Type)
		}
	}

	return ops, nil
}

