// ref_resolver.go resolves $ref pointers in OpenAPI specs by inlining referenced schemas.
package mcp

import (
	"encoding/json"
	"strings"
)

// ResolveRefs resolves $ref pointers in an OpenAPI spec by inlining the referenced schemas.
// This is a simplified resolver that handles the common pattern of $ref pointing to
// #/components/schemas/SchemaName.
func ResolveRefs(spec map[string]any) {
	components, ok := spec["components"].(map[string]any)
	if !ok {
		return
	}
	schemas, ok := components["schemas"].(map[string]any)
	if !ok {
		return
	}

	// Walk the entire spec and resolve all $ref pointers
	resolveRefsInValue(spec, schemas)
}

// resolveRefsInValue recursively walks a JSON structure and resolves $ref pointers.
func resolveRefsInValue(v interface{}, schemas map[string]any) interface{} {
	switch val := v.(type) {
	case map[string]any:
		// Check if this is a $ref object
		if ref, ok := val["$ref"].(string); ok {
			resolved := resolveRef(ref, schemas)
			if resolved != nil {
				return resolved
			}
		}

		// Recursively resolve in all values
		for k, child := range val {
			val[k] = resolveRefsInValue(child, schemas)
		}
		return val

	case []any:
		for i, child := range val {
			val[i] = resolveRefsInValue(child, schemas)
		}
		return val

	default:
		return v
	}
}

// resolveRef resolves a single $ref string like "#/components/schemas/User".
func resolveRef(ref string, schemas map[string]any) map[string]any {
	const prefix = "#/components/schemas/"
	if !strings.HasPrefix(ref, prefix) {
		return nil
	}

	schemaName := ref[len(prefix):]
	schema, ok := schemas[schemaName].(map[string]any)
	if !ok {
		return nil
	}

	// Deep copy to avoid mutating the original schema
	copied := deepCopyMap(schema)

	// Recursively resolve refs within the resolved schema
	resolveRefsInValue(copied, schemas)

	return copied
}

// deepCopyMap creates a deep copy of a map[string]any.
func deepCopyMap(src map[string]any) map[string]any {
	data, err := json.Marshal(src)
	if err != nil {
		return src
	}
	var dst map[string]any
	if err := json.Unmarshal(data, &dst); err != nil {
		return src
	}
	return dst
}
