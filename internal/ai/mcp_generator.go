// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	json "github.com/goccy/go-json"
	"fmt"
	"strings"

	"github.com/soapbucket/sbproxy/internal/extension/mcp"
)

// GenerateFromOpenAPI parses an OpenAPI 3.0 spec and generates MCP ToolConfig entries.
// Each path+method combination becomes an MCP tool. Path parameters, query parameters,
// and request body fields become tool input properties.
func GenerateFromOpenAPI(spec []byte) ([]mcp.ToolConfig, error) {
	var doc openAPIDoc
	if err := json.Unmarshal(spec, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse OpenAPI spec: %w", err)
	}

	if doc.OpenAPI == "" {
		return nil, fmt.Errorf("missing openapi version field")
	}

	var tools []mcp.ToolConfig

	for path, pathItem := range doc.Paths {
		for method, op := range pathItem.Operations() {
			tool, err := operationToTool(path, method, op)
			if err != nil {
				continue // Skip malformed operations
			}
			tools = append(tools, *tool)
		}
	}

	return tools, nil
}

// GenerateFromOriginConfig generates MCP tools from an existing proxy origin config.
// Each path becomes a tool. Query params become tool arguments.
func GenerateFromOriginConfig(routes []OriginRoute) ([]mcp.ToolConfig, error) {
	if len(routes) == 0 {
		return nil, fmt.Errorf("no routes provided")
	}

	var tools []mcp.ToolConfig

	for _, route := range routes {
		tool := originRouteToTool(route)
		tools = append(tools, tool)
	}

	return tools, nil
}

// OriginRoute describes a route from a proxy origin configuration.
type OriginRoute struct {
	Path        string            `json:"path"`
	Method      string            `json:"method"`
	Description string            `json:"description,omitempty"`
	QueryParams []RouteParam      `json:"query_params,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	TargetURL   string            `json:"target_url"`
}

// RouteParam describes a parameter on a route.
type RouteParam struct {
	Name        string `json:"name"`
	Type        string `json:"type"`        // "string", "integer", "boolean"
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// =============================================================================
// OpenAPI parsing types (minimal subset)
// =============================================================================

type openAPIDoc struct {
	OpenAPI string                 `json:"openapi"`
	Info    openAPIInfo            `json:"info"`
	Paths   map[string]openAPIPath `json:"paths"`
}

type openAPIInfo struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Version     string `json:"version"`
}

type openAPIPath struct {
	Get     *openAPIOperation `json:"get,omitempty"`
	Post    *openAPIOperation `json:"post,omitempty"`
	Put     *openAPIOperation `json:"put,omitempty"`
	Delete  *openAPIOperation `json:"delete,omitempty"`
	Patch   *openAPIOperation `json:"patch,omitempty"`
}

// Operations returns a map of method -> operation for non-nil methods.
func (p openAPIPath) Operations() map[string]*openAPIOperation {
	ops := make(map[string]*openAPIOperation)
	if p.Get != nil {
		ops["GET"] = p.Get
	}
	if p.Post != nil {
		ops["POST"] = p.Post
	}
	if p.Put != nil {
		ops["PUT"] = p.Put
	}
	if p.Delete != nil {
		ops["DELETE"] = p.Delete
	}
	if p.Patch != nil {
		ops["PATCH"] = p.Patch
	}
	return ops
}

type openAPIOperation struct {
	OperationID string             `json:"operationId"`
	Summary     string             `json:"summary"`
	Description string             `json:"description"`
	Parameters  []openAPIParameter `json:"parameters"`
	RequestBody *openAPIRequestBody `json:"requestBody"`
}

type openAPIParameter struct {
	Name        string          `json:"name"`
	In          string          `json:"in"` // "path", "query", "header"
	Description string          `json:"description"`
	Required    bool            `json:"required"`
	Schema      json.RawMessage `json:"schema"`
}

type openAPIRequestBody struct {
	Description string                     `json:"description"`
	Required    bool                       `json:"required"`
	Content     map[string]openAPIMediaType `json:"content"`
}

type openAPIMediaType struct {
	Schema json.RawMessage `json:"schema"`
}

// =============================================================================
// Conversion helpers
// =============================================================================

func operationToTool(path, method string, op *openAPIOperation) (*mcp.ToolConfig, error) {
	name := op.OperationID
	if name == "" {
		// Generate name from method + path
		name = strings.ToLower(method) + "_" + pathToName(path)
	}

	description := op.Summary
	if description == "" {
		description = op.Description
	}
	if description == "" {
		description = fmt.Sprintf("%s %s", method, path)
	}

	// Build JSON Schema for input
	properties := make(map[string]any)
	var required []string

	for _, param := range op.Parameters {
		prop := make(map[string]any)
		if param.Schema != nil {
			var schema map[string]any
			if json.Unmarshal(param.Schema, &schema) == nil {
				prop = schema
			}
		}
		if prop["type"] == nil {
			prop["type"] = "string"
		}
		if param.Description != "" {
			prop["description"] = param.Description
		}
		properties[param.Name] = prop

		if param.Required {
			required = append(required, param.Name)
		}
	}

	// Extract request body schema if present
	if op.RequestBody != nil {
		for _, mediaType := range op.RequestBody.Content {
			if mediaType.Schema != nil {
				properties["body"] = json.RawMessage(mediaType.Schema)
				if op.RequestBody.Required {
					required = append(required, "body")
				}
				break
			}
		}
	}

	inputSchema := map[string]any{
		"type":       "object",
		"properties": properties,
	}
	if len(required) > 0 {
		inputSchema["required"] = required
	}

	schemaBytes, err := json.Marshal(inputSchema)
	if err != nil {
		return nil, err
	}

	return &mcp.ToolConfig{
		Name:        name,
		Description: description,
		InputSchema: schemaBytes,
		Handler: mcp.ToolHandler{
			Type: "proxy",
			Proxy: &mcp.ProxyHandler{
				URL:    path,
				Method: method,
			},
		},
	}, nil
}

func originRouteToTool(route OriginRoute) mcp.ToolConfig {
	name := strings.ToLower(route.Method) + "_" + pathToName(route.Path)
	description := route.Description
	if description == "" {
		description = fmt.Sprintf("%s %s", route.Method, route.Path)
	}

	properties := make(map[string]any)
	var required []string

	for _, param := range route.QueryParams {
		prop := map[string]any{
			"type": param.Type,
		}
		if prop["type"] == "" || prop["type"] == nil {
			prop["type"] = "string"
		}
		if param.Description != "" {
			prop["description"] = param.Description
		}
		properties[param.Name] = prop

		if param.Required {
			required = append(required, param.Name)
		}
	}

	// Extract path parameters as {param} patterns
	for _, segment := range strings.Split(route.Path, "/") {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			paramName := segment[1 : len(segment)-1]
			if _, exists := properties[paramName]; !exists {
				properties[paramName] = map[string]any{
					"type":        "string",
					"description": fmt.Sprintf("Path parameter: %s", paramName),
				}
				required = append(required, paramName)
			}
		}
	}

	inputSchema := map[string]any{
		"type":       "object",
		"properties": properties,
	}
	if len(required) > 0 {
		inputSchema["required"] = required
	}

	schemaBytes, _ := json.Marshal(inputSchema)

	return mcp.ToolConfig{
		Name:        name,
		Description: description,
		InputSchema: schemaBytes,
		Handler: mcp.ToolHandler{
			Type: "proxy",
			Proxy: &mcp.ProxyHandler{
				URL:     route.TargetURL + route.Path,
				Method:  route.Method,
				Headers: route.Headers,
			},
		},
	}
}

// pathToName converts a URL path to a tool name.
// e.g., "/api/v1/pets/{petId}" -> "api_v1_pets_petId"
func pathToName(path string) string {
	path = strings.Trim(path, "/")
	path = strings.ReplaceAll(path, "{", "")
	path = strings.ReplaceAll(path, "}", "")
	path = strings.ReplaceAll(path, "/", "_")
	path = strings.ReplaceAll(path, "-", "_")
	return path
}
