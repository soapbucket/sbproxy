// Package mcp implements the Model Context Protocol (MCP) for AI tool and resource integration.
package mcp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/extension/lua"
	templateresolver "github.com/soapbucket/sbproxy/internal/template"
)

// =============================================================================
// Tool Registry
// =============================================================================

// ToolRegistry manages tool registration and lookup.
type ToolRegistry struct {
	tools    map[string]*ToolConfig
	toolList []Tool // Only includes enabled and hidden tools (for callable check)
}

// NewToolRegistry creates a new tool registry.
func NewToolRegistry() *ToolRegistry {
	return &ToolRegistry{
		tools:    make(map[string]*ToolConfig),
		toolList: []Tool{},
	}
}

// Register registers a tool configuration. Disabled tools are silently skipped.
func (r *ToolRegistry) Register(tool ToolConfig) error {
	if tool.Name == "" {
		return fmt.Errorf("tool name is required")
	}

	// Skip disabled tools entirely
	if tool.Visibility == VisibilityDisabled {
		return nil
	}

	if _, exists := r.tools[tool.Name]; exists {
		return fmt.Errorf("tool %s already registered", tool.Name)
	}

	r.tools[tool.Name] = &tool

	// Only add to the public tool list if not hidden
	if tool.Visibility != VisibilityHidden {
		r.toolList = append(r.toolList, Tool{
			Name:        tool.Name,
			Description: tool.Description,
			InputSchema: tool.InputSchema,
			Annotations: tool.Annotations,
		})
	}

	return nil
}

// Get returns a tool by name. Returns an error if the tool is not registered
// (disabled tools are never registered, hidden tools are registered and callable).
func (r *ToolRegistry) Get(name string) (*ToolConfig, error) {
	tool, ok := r.tools[name]
	if !ok {
		return nil, fmt.Errorf("tool not found: %s", name)
	}
	return tool, nil
}

// List returns all visible (non-hidden) registered tools.
func (r *ToolRegistry) List() []Tool {
	return r.toolList
}

// Has returns true if a tool is registered and callable.
func (r *ToolRegistry) Has(name string) bool {
	_, ok := r.tools[name]
	return ok
}

// =============================================================================
// Tool Executor
// =============================================================================

// ToolExecutor executes tools and transforms responses.
type ToolExecutor struct {
	registry            *ToolRegistry
	validator           *SchemaValidator
	httpClient          *http.Client
	insecureHTTPClient  *http.Client
	defaultTimeout      time.Duration
	errorHandler        *ErrorHandler
}

// NewToolExecutor creates a new tool executor.
func NewToolExecutor(registry *ToolRegistry, validator *SchemaValidator, config *Config) *ToolExecutor {
	timeout := 30 * time.Second
	if config != nil && config.DefaultTimeout.Duration > 0 {
		timeout = config.DefaultTimeout.Duration
	}

	insecureTransport := http.DefaultTransport.(*http.Transport).Clone()
	insecureTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // user-configured for test backends

	return &ToolExecutor{
		registry:           registry,
		validator:          validator,
		httpClient:         &http.Client{Timeout: timeout},
		insecureHTTPClient: &http.Client{Timeout: timeout, Transport: insecureTransport},
		defaultTimeout:     timeout,
		errorHandler:       NewErrorHandler(config.ErrorHandling),
	}
}

// Execute executes a tool with the given arguments.
func (e *ToolExecutor) Execute(ctx context.Context, toolName string, args map[string]interface{}) (*ToolResult, *MCPError) {
	// Get tool configuration
	tool, err := e.registry.Get(toolName)
	if err != nil {
		return nil, NewToolNotFoundError(toolName)
	}

	// Validate arguments
	if validationErr := e.validator.Validate(toolName, args); validationErr != nil {
		return nil, validationErr
	}

	// Build execution context
	execCtx := &ToolExecutionContext{
		ToolName:    toolName,
		Arguments:   args,
		Tool:        tool,
		StepResults: make(map[string]interface{}),
	}

	// Determine timeout
	timeout := e.defaultTimeout
	if tool.Timeout.Duration > 0 {
		timeout = tool.Timeout.Duration
	}

	// Execute with timeout
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Execute based on handler type
	var result interface{}
	var execErr error

	switch tool.Handler.Type {
	case "orchestration":
		result, execErr = e.executeOrchestration(ctx, execCtx)
	case "proxy":
		result, execErr = e.executeProxy(ctx, execCtx)
	case "static":
		result, execErr = e.executeStatic(ctx, execCtx)
	default:
		return nil, NewInternalError(fmt.Sprintf("unknown handler type: %s", tool.Handler.Type), nil)
	}

	if execErr != nil {
		return nil, e.errorHandler.WrapError(execErr, toolName)
	}

	// Check for binary response (image/resource content types)
	if binResult, ok := result.(map[string]interface{}); ok {
		if binResult["__binary"] == true {
			return buildBinaryToolResult(binResult), nil
		}
	}

	// Transform response if template or lua is configured
	content, transformErr := e.transformResponse(ctx, execCtx, result)
	if transformErr != nil {
		return nil, NewTransformError(toolName, transformErr.Error(), transformErr)
	}

	return &ToolResult{
		Content: []Content{
			{Type: "text", Text: content},
		},
		IsError: false,
	}, nil
}

// buildBinaryToolResult creates a ToolResult for binary content (images, resources).
func buildBinaryToolResult(binData map[string]interface{}) *ToolResult {
	data, _ := binData["__data"].([]byte)
	mimeType, _ := binData["__mimeType"].(string)
	contentType, _ := binData["__type"].(string)

	encoded := base64.StdEncoding.EncodeToString(data)

	switch contentType {
	case "image":
		return &ToolResult{
			Content: []Content{
				{Type: "image", Data: encoded, MimeType: mimeType},
			},
		}
	case "resource":
		return &ToolResult{
			Content: []Content{
				{Type: "resource", Resource: &ResourceContent{
					URI:      "data:" + mimeType,
					MimeType: mimeType,
					Blob:     encoded,
				}},
			},
		}
	default:
		return &ToolResult{
			Content: []Content{
				{Type: "text", Text: string(data)},
			},
		}
	}
}

// =============================================================================
// Handler Implementations
// =============================================================================

func (e *ToolExecutor) executeOrchestration(ctx context.Context, execCtx *ToolExecutionContext) (interface{}, error) {
	handler := execCtx.Tool.Handler.Orchestration
	if handler == nil {
		return nil, fmt.Errorf("orchestration handler not configured")
	}

	// Build template context with request identity
	templateCtx := buildTemplateContext(ctx, execCtx)
	templateCtx["steps"] = execCtx.StepResults

	// Execute steps
	for _, step := range handler.Steps {
		// Check dependencies
		if len(step.DependsOn) > 0 {
			for _, dep := range step.DependsOn {
				if _, ok := execCtx.StepResults[dep]; !ok {
					return nil, fmt.Errorf("step %s depends on %s which has not completed", step.Name, dep)
				}
			}
		}

		// Check condition if specified
		if step.Condition != "" {
			conditionMet, err := e.evaluateCondition(step.Condition, templateCtx)
			if err != nil {
				return nil, fmt.Errorf("failed to evaluate condition for step %s: %w", step.Name, err)
			}
			if !conditionMet {
				continue // Skip this step
			}
		}

		// Execute step
		stepResult, err := e.executeStep(ctx, step, templateCtx)
		if err != nil {
			if step.ContinueOnError != nil && *step.ContinueOnError {
				execCtx.StepResults[step.Name] = map[string]interface{}{
					"error": err.Error(),
				}
				continue
			}
			return nil, fmt.Errorf("step %s failed: %w", step.Name, err)
		}

		// Store result with response_json for Mustache templates.
		// Wrap array responses so numeric indices work with dot notation
		// (e.g., steps.geocode.response.0.lat).
		wrappedResponse := wrapArrayForMustache(stepResult)
		stepCtx := map[string]interface{}{
			"response": wrappedResponse,
		}
		if b, err := json.Marshal(stepResult); err == nil {
			stepCtx["response_json"] = string(b)
		}
		execCtx.StepResults[step.Name] = stepCtx
		templateCtx["steps"] = execCtx.StepResults
	}

	return execCtx.StepResults, nil
}

func (e *ToolExecutor) executeStep(ctx context.Context, step OrchestrationStep, templateCtx map[string]interface{}) (interface{}, error) {
	// Parse callback config
	var callbackConfig struct {
		URL     string            `json:"url"`
		Method  string            `json:"method"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
		Timeout string            `json:"timeout"`
	}

	if err := json.Unmarshal(step.Callback, &callbackConfig); err != nil {
		return nil, fmt.Errorf("invalid callback config: %w", err)
	}

	// Render URL template
	url, err := e.renderTemplate(callbackConfig.URL, templateCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to render URL template: %w", err)
	}

	// Create request
	method := callbackConfig.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if callbackConfig.Body != "" {
		body, err := e.renderTemplate(callbackConfig.Body, templateCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to render body template: %w", err)
		}
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add headers
	for key, value := range callbackConfig.Headers {
		renderedValue, err := e.renderTemplate(value, templateCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to render header %s: %w", key, err)
		}
		req.Header.Set(key, renderedValue)
	}

	// Execute request
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check status code
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse JSON response
	var result interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		// Return as string if not JSON
		return string(respBody), nil
	}

	return result, nil
}

func (e *ToolExecutor) executeProxy(ctx context.Context, execCtx *ToolExecutionContext) (interface{}, error) {
	handler := execCtx.Tool.Handler.Proxy
	if handler == nil {
		return nil, fmt.Errorf("proxy handler not configured")
	}

	// Route through origin pipeline if origin_host or origin_config is configured
	if handler.HasOriginRouting() {
		return e.executeOriginProxy(ctx, execCtx)
	}

	// Build template context with request identity
	templateCtx := buildTemplateContext(ctx, execCtx)

	// Render URL template
	reqURL, err := e.renderTemplate(handler.URL, templateCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to render URL template: %w", err)
	}

	// Append structured query params with proper URL encoding
	if len(handler.QueryParams) > 0 {
		reqURL, err = e.appendQueryParams(reqURL, handler.QueryParams, templateCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to build query params: %w", err)
		}
	}

	// Create request
	method := handler.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader

	// BodyTemplate takes precedence over Body
	if len(handler.BodyTemplate) > 0 {
		bodyBytes, err := e.renderBodyTemplate(handler.BodyTemplate, templateCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to render body template: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	} else if handler.Body != "" {
		body, err := e.renderTemplate(handler.Body, templateCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to render body template: %w", err)
		}
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set Content-Type for body_template requests
	if len(handler.BodyTemplate) > 0 && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	// Add headers
	for key, value := range handler.Headers {
		renderedValue, err := e.renderTemplate(value, templateCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to render header %s: %w", key, err)
		}
		req.Header.Set(key, renderedValue)
	}

	// Apply per-tool auth if configured
	if handler.Auth != nil {
		authProvider := NewToolAuthProvider(handler.Auth)
		if err := authProvider.ApplyAuth(req); err != nil {
			return nil, fmt.Errorf("failed to apply tool auth: %w", err)
		}
	}

	// Select HTTP client based on TLS verification setting
	client := e.httpClient
	if handler.SkipTLSVerifyHost {
		client = e.insecureHTTPClient
	}

	// Handle pagination if configured
	if handler.Pagination != nil {
		renderedHeaders := make(map[string]string)
		for k := range req.Header {
			renderedHeaders[k] = req.Header.Get(k)
		}
		return executePaginated(ctx, client, reqURL, method, renderedHeaders, handler.Pagination)
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check status code - apply error mapping if configured
	if resp.StatusCode >= 400 {
		if len(handler.ErrorMapping) > 0 {
			if mapped := matchErrorMapping(handler.ErrorMapping, resp.StatusCode, execCtx, string(respBody), e.renderTemplate); mapped != "" {
				return nil, &mappedToolError{message: mapped}
			}
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	// Handle content_type for non-text responses
	if handler.ContentType == "image" || handler.ContentType == "resource" {
		return handleBinaryResponse(respBody, resp.Header.Get("Content-Type"), handler), nil
	}
	if handler.ContentType == "auto" {
		ct := resp.Header.Get("Content-Type")
		if strings.HasPrefix(ct, "image/") {
			// Override content type to "image" for auto-detection
			autoHandler := *handler
			autoHandler.ContentType = "image"
			return handleBinaryResponse(respBody, ct, &autoHandler), nil
		}
	}

	// Parse JSON response
	var result interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		// Return as string if not JSON
		return string(respBody), nil
	}

	// Apply response mapping if configured
	if len(handler.ResponseMapping) > 0 {
		result = applyResponseMapping(result, handler.ResponseMapping)
	}

	return result, nil
}

// handleBinaryResponse wraps binary response data for non-text content types.
// The result is a map that transformResponse will serialize appropriately.
func handleBinaryResponse(data []byte, contentType string, handler *ProxyHandler) map[string]interface{} {
	mimeType := handler.ContentMimeType
	if mimeType == "" {
		mimeType = contentType
	}

	return map[string]interface{}{
		"__binary":   true,
		"__data":     data,
		"__mimeType": mimeType,
		"__type":     handler.ContentType,
	}
}

// executeOriginProxy executes a proxy handler by routing the request through
// a resolved origin's full pipeline (transforms, modifiers, policies) using an
// httptest.ResponseRecorder to capture the response.
func (e *ToolExecutor) executeOriginProxy(ctx context.Context, execCtx *ToolExecutionContext) (interface{}, error) {
	handler := execCtx.Tool.Handler.Proxy
	if handler.resolvedOriginHandler == nil {
		return nil, fmt.Errorf("origin handler not resolved for tool %s", execCtx.ToolName)
	}

	// Build template context
	templateCtx := buildTemplateContext(ctx, execCtx)

	// Build the request URL. For origin routing, if URL is empty, default to "/"
	reqURL := "/"
	if handler.URL != "" {
		var err error
		reqURL, err = e.renderTemplate(handler.URL, templateCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to render URL template: %w", err)
		}
	}

	// Append structured query params
	if len(handler.QueryParams) > 0 {
		var err error
		reqURL, err = e.appendQueryParams(reqURL, handler.QueryParams, templateCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to build query params: %w", err)
		}
	}

	// Build method
	method := handler.Method
	if method == "" {
		method = "GET"
	}

	// Build body
	var bodyReader io.Reader
	if len(handler.BodyTemplate) > 0 {
		bodyBytes, err := e.renderBodyTemplate(handler.BodyTemplate, templateCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to render body template: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	} else if handler.Body != "" {
		body, err := e.renderTemplate(handler.Body, templateCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to render body template: %w", err)
		}
		bodyReader = strings.NewReader(body)
	}

	// Create the request to pass through the origin pipeline
	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set Content-Type for body_template requests
	if len(handler.BodyTemplate) > 0 && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	// Add headers
	for key, value := range handler.Headers {
		renderedValue, err := e.renderTemplate(value, templateCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to render header %s: %w", key, err)
		}
		req.Header.Set(key, renderedValue)
	}

	// Execute via ResponseRecorder through the origin pipeline
	recorder := httptest.NewRecorder()
	handler.resolvedOriginHandler.ServeHTTP(recorder, req)

	respBody := recorder.Body.Bytes()

	// Check status code - apply error mapping if configured
	if recorder.Code >= 400 {
		if len(handler.ErrorMapping) > 0 {
			if mapped := matchErrorMapping(handler.ErrorMapping, recorder.Code, execCtx, string(respBody), e.renderTemplate); mapped != "" {
				return nil, &mappedToolError{message: mapped}
			}
		}
		return nil, fmt.Errorf("HTTP %d: %s", recorder.Code, string(respBody))
	}

	// Handle content_type for non-text responses
	if handler.ContentType == "image" || handler.ContentType == "resource" {
		return handleBinaryResponse(respBody, recorder.Header().Get("Content-Type"), handler), nil
	}
	if handler.ContentType == "auto" {
		ct := recorder.Header().Get("Content-Type")
		if strings.HasPrefix(ct, "image/") {
			autoHandler := *handler
			autoHandler.ContentType = "image"
			return handleBinaryResponse(respBody, ct, &autoHandler), nil
		}
	}

	// Parse JSON response
	var result interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		// Return as string if not JSON
		return string(respBody), nil
	}

	// Apply response mapping if configured
	if len(handler.ResponseMapping) > 0 {
		result = applyResponseMapping(result, handler.ResponseMapping)
	}

	return result, nil
}

// mappedToolError is a special error type for error_mapping results.
// When the ErrorHandler encounters this, it returns a ToolResult with isError: true
// instead of a JSON-RPC error.
type mappedToolError struct {
	message string
}

func (e *mappedToolError) Error() string {
	return e.message
}

// matchErrorMapping finds a matching error mapping for the given status code.
// Supports exact codes ("404") and wildcard ranges ("4xx", "5xx").
func matchErrorMapping(
	mapping map[string]string,
	statusCode int,
	execCtx *ToolExecutionContext,
	responseBody string,
	render func(string, map[string]interface{}) (string, error),
) string {
	codeStr := fmt.Sprintf("%d", statusCode)
	rangeStr := fmt.Sprintf("%dxx", statusCode/100)

	// Try exact match first, then range
	tmpl, ok := mapping[codeStr]
	if !ok {
		tmpl, ok = mapping[rangeStr]
	}
	if !ok {
		return ""
	}

	// Build template context for error message
	ctx := map[string]interface{}{
		"arguments":    execCtx.Arguments,
		"status_code":  statusCode,
		"response_body": responseBody,
	}

	rendered, err := render(tmpl, ctx)
	if err != nil {
		return tmpl // Fall back to raw template if rendering fails
	}
	return rendered
}

// appendQueryParams renders and appends structured query parameters to a URL with proper encoding.
func (e *ToolExecutor) appendQueryParams(baseURL string, params map[string]string, templateCtx map[string]interface{}) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}

	q := parsed.Query()
	for key, valueTmpl := range params {
		rendered, err := e.renderTemplate(valueTmpl, templateCtx)
		if err != nil {
			return "", fmt.Errorf("failed to render query param %s: %w", key, err)
		}
		if rendered == "" {
			continue
		}
		q.Set(key, rendered)
	}
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}

// renderBodyTemplate walks a structured JSON body template, rendering Mustache in all string values.
func (e *ToolExecutor) renderBodyTemplate(tmpl map[string]interface{}, templateCtx map[string]interface{}) ([]byte, error) {
	rendered, err := renderTemplateValue(tmpl, templateCtx, e.renderTemplate)
	if err != nil {
		return nil, err
	}
	return json.Marshal(rendered)
}

// renderTemplateValue recursively walks a value, rendering Mustache templates in strings.
func renderTemplateValue(v interface{}, ctx map[string]interface{}, render func(string, map[string]interface{}) (string, error)) (interface{}, error) {
	switch val := v.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{}, len(val))
		for k, child := range val {
			rendered, err := renderTemplateValue(child, ctx, render)
			if err != nil {
				return nil, fmt.Errorf("field %s: %w", k, err)
			}
			result[k] = rendered
		}
		return result, nil
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, child := range val {
			rendered, err := renderTemplateValue(child, ctx, render)
			if err != nil {
				return nil, fmt.Errorf("index %d: %w", i, err)
			}
			result[i] = rendered
		}
		return result, nil
	case string:
		return render(val, ctx)
	default:
		return v, nil
	}
}

// applyResponseMapping extracts fields from a response using dot-path notation.
func applyResponseMapping(data interface{}, mapping map[string]string) interface{} {
	result := make(map[string]interface{}, len(mapping))
	for outputKey, path := range mapping {
		result[outputKey] = extractByPath(data, path)
	}
	return result
}

// extractByPath navigates a nested JSON structure using a dot-separated path.
// Supports paths like "data.user.name" or "items.0.id".
func extractByPath(data interface{}, path string) interface{} {
	parts := strings.Split(path, ".")
	current := data
	for _, part := range parts {
		if current == nil {
			return nil
		}
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		case []interface{}:
			idx, err := strconv.Atoi(part)
			if err != nil || idx < 0 || idx >= len(v) {
				return nil
			}
			current = v[idx]
		default:
			return nil
		}
	}
	return current
}

func (e *ToolExecutor) executeStatic(ctx context.Context, execCtx *ToolExecutionContext) (interface{}, error) {
	handler := execCtx.Tool.Handler.Static
	if handler == nil {
		return nil, fmt.Errorf("static handler not configured")
	}

	// Build template context with request identity
	templateCtx := buildTemplateContext(ctx, execCtx)

	// Render content template
	content, err := e.renderTemplate(handler.Content, templateCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to render content template: %w", err)
	}

	// Try to parse as JSON
	var result interface{}
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return content, nil
	}

	return result, nil
}

// =============================================================================
// Response Transformation
// =============================================================================

func (e *ToolExecutor) transformResponse(ctx context.Context, execCtx *ToolExecutionContext, result interface{}) (string, error) {
	handler := execCtx.Tool.Handler

	// Use Lua transformation if configured
	if handler.LuaScript != "" {
		transformed, err := e.executeLuaTransform(ctx, handler.LuaScript, result, execCtx)
		if err != nil {
			return "", fmt.Errorf("lua transform failed: %w", err)
		}
		result = transformed
	}

	// Use template if configured
	if handler.ResponseTemplate != "" {
		templateCtx := buildTemplateContext(ctx, execCtx)
		templateCtx["result"] = result
		templateCtx["steps"] = execCtx.StepResults
		templateCtx["arguments"] = execCtx.Arguments
		return e.renderTemplate(handler.ResponseTemplate, templateCtx)
	}

	// Default: JSON marshal the result
	switch v := result.(type) {
	case string:
		return v, nil
	default:
		data, err := json.Marshal(result)
		if err != nil {
			return "", fmt.Errorf("failed to marshal result: %w", err)
		}
		return string(data), nil
	}
}

func (e *ToolExecutor) executeLuaTransform(ctx context.Context, script string, data interface{}, execCtx *ToolExecutionContext) (interface{}, error) {
	transformer, err := lua.NewJSONTransformer(script)
	if err != nil {
		return nil, fmt.Errorf("failed to create lua transformer: %w", err)
	}

	// Create a fake response for the transformer
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data for lua: %w", err)
	}

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(dataBytes)),
	}

	if err := transformer.TransformResponse(resp); err != nil {
		return nil, err
	}

	// Read transformed body
	transformedBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read transformed data: %w", err)
	}

	var result interface{}
	if err := json.Unmarshal(transformedBytes, &result); err != nil {
		return string(transformedBytes), nil
	}

	return result, nil
}

// =============================================================================
// Template Helpers
// =============================================================================

// buildTemplateContext creates the base template context for tool execution,
// including tool info, arguments, and request identity from the Go context.
func buildTemplateContext(ctx context.Context, execCtx *ToolExecutionContext) map[string]interface{} {
	templateCtx := map[string]interface{}{
		"tool": map[string]interface{}{
			"name":      execCtx.ToolName,
			"arguments": execCtx.Arguments,
		},
	}
	templateresolver.AddLambdas(templateCtx)

	// Add request context (identity from auth middleware)
	roles, keyID := extractIdentity(ctx)
	requestCtx := map[string]interface{}{}
	if len(roles) > 0 {
		requestCtx["roles"] = roles
	}
	if keyID != "" {
		requestCtx["key_id"] = keyID
	}
	if len(requestCtx) > 0 {
		templateCtx["request"] = requestCtx
	}

	return templateCtx
}

func (e *ToolExecutor) renderTemplate(tmpl string, ctx map[string]interface{}) (string, error) {
	return templateresolver.ResolveWithContext(tmpl, ctx)
}

// wrapArrayForMustache converts top-level slice responses to maps with string
// numeric keys so that Mustache dot notation (e.g., response.0.lat) works.
// Nested slices within maps are left unchanged since they work with {{#section}} iteration.
func wrapArrayForMustache(v interface{}) interface{} {
	slice, ok := v.([]interface{})
	if !ok {
		return v
	}
	result := make(map[string]interface{}, len(slice))
	for i, elem := range slice {
		result[strconv.Itoa(i)] = elem
	}
	return result
}

func (e *ToolExecutor) evaluateCondition(condition string, ctx map[string]interface{}) (bool, error) {
	result, err := e.renderTemplate(condition, ctx)
	if err != nil {
		return false, err
	}

	// Check for truthy values
	result = strings.TrimSpace(strings.ToLower(result))
	return result == "true" || result == "1" || result == "yes", nil
}
