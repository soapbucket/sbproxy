package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
)

// OpenAPIBridgeConfig configures automatic MCP tool generation from an OpenAPI spec.
type OpenAPIBridgeConfig struct {
	SpecURL     string            `json:"spec_url,omitempty"`     // URL to fetch OpenAPI spec
	SpecInline  json.RawMessage   `json:"spec_inline,omitempty"`  // Inline OpenAPI spec
	Prefix      string            `json:"prefix,omitempty"`       // Prefix for generated tool names
	AuthHeaders map[string]string `json:"auth_headers,omitempty"` // Headers to forward to the API
	BaseURL     string            `json:"base_url,omitempty"`     // Override API base URL from spec

	// IncludeOperations filters by operationId. Only matching operations are included.
	IncludeOperations []string `json:"include_operations,omitempty"`
	// ExcludeOperations filters out specific operationIds.
	ExcludeOperations []string `json:"exclude_operations,omitempty"`
	// ExcludePaths filters out paths matching glob patterns (e.g., "/admin/*").
	ExcludePaths []string `json:"exclude_paths,omitempty"`
	// ExcludeMethods filters out specific HTTP methods (e.g., "DELETE", "PATCH").
	ExcludeMethods []string `json:"exclude_methods,omitempty"`
	// OperationOverrides allows overriding properties on specific operations by operationId.
	OperationOverrides map[string]*OperationOverride `json:"operation_overrides,omitempty"`
}

// OperationOverride allows overriding properties of a generated tool.
type OperationOverride struct {
	Name            string            `json:"name,omitempty"`
	Description     string            `json:"description,omitempty"`
	ResponseMapping map[string]string `json:"response_mapping,omitempty"`
	Annotations     *ToolAnnotations  `json:"annotations,omitempty"`
	Tags            []string          `json:"tags,omitempty"`
}

// OpenAPIBridge generates MCP tools from OpenAPI specs and proxies tool calls to REST APIs.
type OpenAPIBridge struct {
	config  OpenAPIBridgeConfig
	tools   []BridgedTool
	client  *http.Client
	baseURL string
}

// BridgedTool represents an MCP tool generated from an OpenAPI endpoint.
type BridgedTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Method      string          `json:"-"`
	Path        string          `json:"-"`
	PathParams  []string        `json:"-"`
	QueryParams []string        `json:"-"`
	HasBody     bool            `json:"-"`
}

// NewOpenAPIBridge creates a bridge from an OpenAPI specification.
func NewOpenAPIBridge(cfg OpenAPIBridgeConfig, client *http.Client) (*OpenAPIBridge, error) {
	bridge := &OpenAPIBridge{
		config: cfg,
		client: client,
	}

	var spec map[string]any
	if len(cfg.SpecInline) > 0 {
		if err := json.Unmarshal(cfg.SpecInline, &spec); err != nil {
			return nil, fmt.Errorf("openapi_bridge: invalid inline spec: %w", err)
		}
	} else if cfg.SpecURL != "" {
		var err error
		spec, err = bridge.fetchSpec(cfg.SpecURL)
		if err != nil {
			return nil, fmt.Errorf("openapi_bridge: failed to fetch spec: %w", err)
		}
	} else {
		return nil, fmt.Errorf("openapi_bridge: spec_url or spec_inline is required")
	}

	// Resolve $ref pointers before parsing
	ResolveRefs(spec)

	if err := bridge.parseSpec(spec); err != nil {
		return nil, err
	}

	return bridge, nil
}

// Tools returns the generated MCP tools.
func (b *OpenAPIBridge) Tools() []BridgedTool {
	return b.tools
}

// ToMCPTools converts BridgedTools into MCP Tool definitions suitable for
// tools/list responses. This is the primary entry point for auto-generating
// MCP tool definitions from an OpenAPI spec.
func (b *OpenAPIBridge) ToMCPTools() []Tool {
	tools := make([]Tool, len(b.tools))
	for i, bt := range b.tools {
		tools[i] = Tool{
			Name:        bt.Name,
			Description: bt.Description,
			InputSchema: bt.InputSchema,
		}
	}
	return tools
}

// GenerateToolsFromOpenAPI is a convenience function that parses an OpenAPI spec
// (provided as raw JSON) and returns MCP Tool definitions. One tool is generated
// per operation (path + method). Tool names come from operationId when available,
// otherwise from the path and method. Tool parameters are derived from path params,
// query params, and request body schema.
func GenerateToolsFromOpenAPI(specJSON []byte, cfg OpenAPIBridgeConfig) ([]Tool, error) {
	if len(cfg.SpecInline) == 0 && cfg.SpecURL == "" {
		cfg.SpecInline = specJSON
	}
	bridge, err := NewOpenAPIBridge(cfg, http.DefaultClient)
	if err != nil {
		return nil, err
	}
	return bridge.ToMCPTools(), nil
}

// Execute calls the REST API for a given tool with arguments.
func (b *OpenAPIBridge) Execute(ctx context.Context, toolName string, args json.RawMessage) (json.RawMessage, error) {
	var tool *BridgedTool
	for i := range b.tools {
		if b.tools[i].Name == toolName {
			tool = &b.tools[i]
			break
		}
	}
	if tool == nil {
		return nil, fmt.Errorf("openapi_bridge: tool %q not found", toolName)
	}

	var params map[string]any
	if len(args) > 0 {
		if err := json.Unmarshal(args, &params); err != nil {
			return nil, fmt.Errorf("openapi_bridge: invalid arguments: %w", err)
		}
	}

	// Build URL with path parameters
	path := tool.Path
	for _, p := range tool.PathParams {
		if val, ok := params[p]; ok {
			path = strings.ReplaceAll(path, "{"+p+"}", fmt.Sprintf("%v", val))
			delete(params, p)
		}
	}

	url := strings.TrimRight(b.baseURL, "/") + path

	// Add query parameters
	var queryParts []string
	for _, q := range tool.QueryParams {
		if val, ok := params[q]; ok {
			queryParts = append(queryParts, fmt.Sprintf("%s=%v", q, val))
			delete(params, q)
		}
	}
	if len(queryParts) > 0 {
		url += "?" + strings.Join(queryParts, "&")
	}

	// Build request body from remaining params
	var bodyReader io.Reader
	if tool.HasBody && len(params) > 0 {
		bodyBytes, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		bodyReader = strings.NewReader(string(bodyBytes))
	}

	req, err := http.NewRequestWithContext(ctx, tool.Method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	if bodyReader != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range b.config.AuthHeaders {
		req.Header.Set(k, v)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openapi_bridge: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("openapi_bridge: API returned %d: %s", resp.StatusCode, string(respBody))
	}

	// If the response is valid JSON, return as-is
	if json.Valid(respBody) {
		return respBody, nil
	}
	// Wrap non-JSON in a text result
	result, _ := json.Marshal(map[string]string{"text": string(respBody)})
	return result, nil
}

func (b *OpenAPIBridge) fetchSpec(url string) (map[string]any, error) {
	resp, err := b.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("spec fetch returned %d", resp.StatusCode)
	}

	var spec map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&spec); err != nil {
		return nil, err
	}
	return spec, nil
}

func (b *OpenAPIBridge) parseSpec(spec map[string]any) error {
	// Extract base URL from servers
	if b.config.BaseURL != "" {
		b.baseURL = b.config.BaseURL
	} else if servers, ok := spec["servers"].([]any); ok && len(servers) > 0 {
		if server, ok := servers[0].(map[string]any); ok {
			if url, ok := server["url"].(string); ok {
				b.baseURL = url
			}
		}
	}
	if b.baseURL == "" {
		return fmt.Errorf("openapi_bridge: no base URL found in spec and base_url not configured")
	}

	// Parse paths
	paths, ok := spec["paths"].(map[string]any)
	if !ok {
		return fmt.Errorf("openapi_bridge: no paths found in spec")
	}

	prefix := b.config.Prefix

	// Build method exclusion set
	excludeMethods := make(map[string]bool, len(b.config.ExcludeMethods))
	for _, m := range b.config.ExcludeMethods {
		excludeMethods[strings.ToUpper(m)] = true
	}

	// Build operation include/exclude sets
	includeOps := make(map[string]bool, len(b.config.IncludeOperations))
	for _, op := range b.config.IncludeOperations {
		includeOps[op] = true
	}
	excludeOps := make(map[string]bool, len(b.config.ExcludeOperations))
	for _, op := range b.config.ExcludeOperations {
		excludeOps[op] = true
	}

	for apiPath, methods := range paths {
		// Check path exclusions
		if b.isPathExcluded(apiPath) {
			continue
		}

		methodMap, ok := methods.(map[string]any)
		if !ok {
			continue
		}
		for method, opObj := range methodMap {
			method = strings.ToUpper(method)
			if method != "GET" && method != "POST" && method != "PUT" && method != "PATCH" && method != "DELETE" {
				continue
			}

			// Check method exclusions
			if excludeMethods[method] {
				continue
			}

			op, ok := opObj.(map[string]any)
			if !ok {
				continue
			}

			// Check operation ID filters
			opID, _ := op["operationId"].(string)
			if opID != "" {
				if len(includeOps) > 0 && !includeOps[opID] {
					continue
				}
				if excludeOps[opID] {
					continue
				}
			}

			tool := b.buildTool(prefix, apiPath, method, op)
			if tool == nil {
				continue
			}

			// Apply operation overrides
			if opID != "" {
				if override, ok := b.config.OperationOverrides[opID]; ok {
					if override.Name != "" {
						tool.Name = override.Name
					}
					if override.Description != "" {
						tool.Description = override.Description
					}
				}
			}

			b.tools = append(b.tools, *tool)
		}
	}

	return nil
}

// isPathExcluded checks if a path matches any exclude_paths glob pattern.
func (b *OpenAPIBridge) isPathExcluded(apiPath string) bool {
	for _, pattern := range b.config.ExcludePaths {
		if matched, _ := path.Match(pattern, apiPath); matched {
			return true
		}
	}
	return false
}

func (b *OpenAPIBridge) buildTool(prefix, path, method string, op map[string]any) *BridgedTool {
	// Generate tool name from operationId or path+method
	name := ""
	if opID, ok := op["operationId"].(string); ok {
		name = opID
	} else {
		// Convert path to name: /users/{id}/posts -> users_id_posts
		cleaned := strings.ReplaceAll(path, "/", "_")
		cleaned = strings.ReplaceAll(cleaned, "{", "")
		cleaned = strings.ReplaceAll(cleaned, "}", "")
		cleaned = strings.Trim(cleaned, "_")
		name = strings.ToLower(method) + "_" + cleaned
	}
	if prefix != "" {
		name = prefix + name
	}

	description := ""
	if summary, ok := op["summary"].(string); ok {
		description = summary
	} else if desc, ok := op["description"].(string); ok {
		description = desc
	}

	// Build input schema from parameters and request body
	properties := map[string]any{}
	required := []string{}
	var pathParams, queryParams []string
	hasBody := false

	// Parse parameters
	if params, ok := op["parameters"].([]any); ok {
		for _, p := range params {
			param, ok := p.(map[string]any)
			if !ok {
				continue
			}
			paramName, _ := param["name"].(string)
			paramIn, _ := param["in"].(string)
			paramDesc, _ := param["description"].(string)
			paramRequired, _ := param["required"].(bool)

			prop := map[string]any{"type": "string"}
			if schema, ok := param["schema"].(map[string]any); ok {
				prop = schema
			}
			if paramDesc != "" {
				prop["description"] = paramDesc
			}
			properties[paramName] = prop

			if paramRequired {
				required = append(required, paramName)
			}
			switch paramIn {
			case "path":
				pathParams = append(pathParams, paramName)
			case "query":
				queryParams = append(queryParams, paramName)
			}
		}
	}

	// Parse request body schema
	if reqBody, ok := op["requestBody"].(map[string]any); ok {
		hasBody = true
		if content, ok := reqBody["content"].(map[string]any); ok {
			if jsonContent, ok := content["application/json"].(map[string]any); ok {
				if schema, ok := jsonContent["schema"].(map[string]any); ok {
					// Merge body schema properties into tool properties
					if bodyProps, ok := schema["properties"].(map[string]any); ok {
						for k, v := range bodyProps {
							properties[k] = v
						}
					}
					if bodyRequired, ok := schema["required"].([]any); ok {
						for _, r := range bodyRequired {
							if s, ok := r.(string); ok {
								required = append(required, s)
							}
						}
					}
				}
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

	return &BridgedTool{
		Name:        name,
		Description: description,
		InputSchema: schemaBytes,
		Method:      method,
		Path:        path,
		PathParams:  pathParams,
		QueryParams: queryParams,
		HasBody:     hasBody,
	}
}
