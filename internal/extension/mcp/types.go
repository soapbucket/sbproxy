// Package mcp implements the Model Context Protocol (MCP) server functionality.
// MCP is a protocol developed by Anthropic that enables LLM applications to
// integrate with external data sources and tools via JSON-RPC 2.0.
package mcp

import (
	"encoding/json"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// Protocol version supported by this implementation
const ProtocolVersion = "2025-06-18"

// Tool visibility constants
const (
	// VisibilityEnabled means the tool is listed and callable (default).
	VisibilityEnabled = "enabled"
	// VisibilityHidden means the tool is callable but omitted from tools/list.
	VisibilityHidden = "hidden"
	// VisibilityDisabled means the tool is neither listed nor callable.
	VisibilityDisabled = "disabled"
)

// =============================================================================
// JSON-RPC 2.0 Types
// =============================================================================

// JSONRPCRequest represents a JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"` // Can be string, number, or null
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      interface{}   `json:"id,omitempty"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

// JSONRPCError represents a JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// =============================================================================
// MCP Protocol Types
// =============================================================================

// ServerInfo contains metadata about the MCP server.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ClientInfo contains metadata about the MCP client.
type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Capabilities describes the features supported by the server.
type Capabilities struct {
	Tools     *ToolsCapability     `json:"tools,omitempty"`
	Resources *ResourcesCapability `json:"resources,omitempty"`
	Prompts   *PromptsCapability   `json:"prompts,omitempty"`
}

// ToolsCapability indicates tool support.
type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ResourcesCapability indicates resource support.
type ResourcesCapability struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}

// PromptsCapability indicates prompt support.
type PromptsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// =============================================================================
// Initialize Types
// =============================================================================

// InitializeParams contains the parameters for the initialize request.
type InitializeParams struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    Capabilities `json:"capabilities"`
	ClientInfo      ClientInfo   `json:"clientInfo"`
}

// InitializeResult contains the result of the initialize request.
type InitializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    Capabilities `json:"capabilities"`
	ServerInfo      ServerInfo   `json:"serverInfo"`
}

// =============================================================================
// Tool Types
// =============================================================================

// ToolAnnotations contains hints about tool behavior per MCP 2025-06-18 spec.
type ToolAnnotations struct {
	// ReadOnlyHint indicates the tool only reads data and does not modify state.
	ReadOnlyHint *bool `json:"readOnlyHint,omitempty"`
	// DestructiveHint indicates the tool may perform destructive operations.
	DestructiveHint *bool `json:"destructiveHint,omitempty"`
	// IdempotentHint indicates repeated calls with the same args have the same effect.
	IdempotentHint *bool `json:"idempotentHint,omitempty"`
	// OpenWorldHint indicates the tool interacts with external systems.
	OpenWorldHint *bool `json:"openWorldHint,omitempty"`
}

// Tool represents an MCP tool definition.
type Tool struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	InputSchema json.RawMessage  `json:"inputSchema"`
	Annotations *ToolAnnotations `json:"annotations,omitempty"`
}

// ListToolsResult contains the result of tools/list.
type ListToolsResult struct {
	Tools      []Tool `json:"tools"`
	NextCursor string `json:"nextCursor,omitempty"`
}

// ToolCallParams contains the parameters for tools/call.
type ToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// ToolResult contains the result of a tool execution.
type ToolResult struct {
	Content []Content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

// Content represents content returned by a tool.
type Content struct {
	Type     string           `json:"type"` // "text", "image", "resource"
	Text     string           `json:"text,omitempty"`
	Data     string           `json:"data,omitempty"`     // base64 for images
	MimeType string           `json:"mimeType,omitempty"` // for images
	Resource *ResourceContent `json:"resource,omitempty"`
}

// ResourceContent represents embedded resource content.
type ResourceContent struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
	Blob     string `json:"blob,omitempty"` // base64
}

// =============================================================================
// Resource Types
// =============================================================================

// Resource represents an MCP resource definition.
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// ListResourcesResult contains the result of resources/list.
type ListResourcesResult struct {
	Resources  []Resource `json:"resources"`
	NextCursor string     `json:"nextCursor,omitempty"`
}

// ReadResourceParams contains the parameters for resources/read.
type ReadResourceParams struct {
	URI string `json:"uri"`
}

// ReadResourceResult contains the result of resources/read.
type ReadResourceResult struct {
	Contents []ResourceContent `json:"contents"`
}

// =============================================================================
// Configuration Types
// =============================================================================

// MCP server mode constants
const (
	// ModeOrchestrator creates MCP tools from local config (proxy, static, orchestration handlers).
	// This is the default mode.
	ModeOrchestrator = "orchestrator"
	// ModeGateway proxies MCP requests to upstream MCP servers with added auth/filtering.
	ModeGateway = "gateway"
)

// Config defines the complete MCP server configuration.
type Config struct {
	// Mode: "orchestrator" (default) or "gateway"
	Mode string `json:"mode,omitempty"`

	// ServerInfo for initialize response
	ServerInfo ServerInfo `json:"server_info"`

	// Capabilities advertised to clients
	Capabilities Capabilities `json:"capabilities"`

	// Tools available on this server (orchestrator mode)
	Tools []ToolConfig `json:"tools"`

	// Resources available on this server (optional)
	Resources []ResourceConfig `json:"resources,omitempty"`

	// Prompts available on this server (optional)
	Prompts []PromptConfig `json:"prompts,omitempty"`

	// FederatedServers for tool discovery from upstream MCP servers (both modes)
	FederatedServers []FederatedServerConfig `json:"federated_servers,omitempty"`

	// ErrorHandling configuration
	ErrorHandling *ErrorHandlingConfig `json:"error_handling,omitempty"`

	// DefaultTimeout for tool execution
	DefaultTimeout reqctx.Duration `json:"default_timeout,omitempty" validate:"max_value=5m,default_value=30s"`

	// ToolCache enables tool result caching
	ToolCache *ToolCacheConfig `json:"tool_cache,omitempty"`

	// LogLevel for MCP logging capability (debug, info, warning, error)
	LogLevel string `json:"log_level,omitempty"`

	// OriginResolver resolves origin references into http.Handlers.
	// Set by the config layer during initialization. Used to resolve
	// origin_host and origin_config fields on proxy handlers.
	OriginResolver OriginResolver `json:"-"`
}

// ToolCacheConfig configures tool result caching.
type ToolCacheConfig struct {
	Enabled    bool            `json:"enabled"`
	DefaultTTL reqctx.Duration `json:"default_ttl,omitempty" validate:"max_value=1h,default_value=2m"`
	MaxEntries int             `json:"max_entries,omitempty" validate:"default_value=1000"`
}

// ToolCacheEntry configures caching for a specific tool.
type ToolCacheEntry struct {
	// TTL for cached results. Required.
	TTL reqctx.Duration `json:"ttl"`
	// Scope: "shared" (default), "per_user", "per_key"
	Scope string `json:"scope,omitempty"`
	// Key is a Mustache template for cache key generation.
	Key string `json:"key,omitempty"`
}

// PromptConfig defines an MCP prompt template.
type PromptConfig struct {
	Name        string               `json:"name"`
	Description string               `json:"description,omitempty"`
	Arguments   []PromptArgument     `json:"arguments,omitempty"`
	Messages    []PromptMessage      `json:"messages"`
}

// PromptArgument defines an argument for a prompt template.
type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// PromptMessage defines a message in a prompt template.
type PromptMessage struct {
	Role    string `json:"role"` // "user" or "assistant"
	Content string `json:"content"` // Mustache template
}

// Prompt represents an MCP prompt definition in protocol responses.
type Prompt struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
}

// ListPromptsResult contains the result of prompts/list.
type ListPromptsResult struct {
	Prompts    []Prompt `json:"prompts"`
	NextCursor string   `json:"nextCursor,omitempty"`
}

// GetPromptParams contains the parameters for prompts/get.
type GetPromptParams struct {
	Name      string            `json:"name"`
	Arguments map[string]string `json:"arguments,omitempty"`
}

// GetPromptResult contains the result of prompts/get.
type GetPromptResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []PromptResultMessage `json:"messages"`
}

// PromptResultMessage is a rendered message in a prompt result.
type PromptResultMessage struct {
	Role    string  `json:"role"`
	Content Content `json:"content"`
}

// ToolConfig defines a tool's configuration.
type ToolConfig struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`

	// Handler defines how to execute this tool
	Handler ToolHandler `json:"handler"`

	// Timeout for this specific tool (overrides default)
	Timeout reqctx.Duration `json:"timeout,omitempty" validate:"max_value=5m"`

	// RetryPolicy for this tool
	RetryPolicy *RetryPolicy `json:"retry_policy,omitempty"`

	// Visibility controls whether the tool is listed and callable.
	// Values: "enabled" (default), "hidden" (callable but not listed), "disabled" (inactive).
	Visibility string `json:"visibility,omitempty"`

	// Tags for categorization and bulk filtering.
	Tags []string `json:"tags,omitempty"`

	// Annotations provides hints about tool behavior per MCP 2025-06-18 spec.
	Annotations *ToolAnnotations `json:"annotations,omitempty"`

	// Access configures per-tool access control.
	Access *ToolAccessConfig `json:"access,omitempty"`

	// Cache configures result caching for this tool.
	Cache *ToolCacheEntry `json:"cache,omitempty"`
}

// ToolHandler defines how a tool is executed.
type ToolHandler struct {
	// Type: "orchestration", "proxy", "static", "lua"
	Type string `json:"type"`

	// Orchestration handler config
	Orchestration *OrchestrationHandler `json:"orchestration,omitempty"`

	// Proxy handler config
	Proxy *ProxyHandler `json:"proxy,omitempty"`

	// Static handler config
	Static *StaticHandler `json:"static,omitempty"`

	// Response transformation
	ResponseTemplate string `json:"response_template,omitempty"`
	LuaScript        string `json:"lua_script,omitempty"`
}

// OrchestrationHandler executes multi-step workflows.
type OrchestrationHandler struct {
	Steps           []OrchestrationStep `json:"steps"`
	Parallel        bool                `json:"parallel,omitempty"`
	Timeout         reqctx.Duration     `json:"timeout,omitempty" validate:"max_value=5m"`
	ContinueOnError bool                `json:"continue_on_error,omitempty"`
}

// OrchestrationStep defines a single step in orchestration.
type OrchestrationStep struct {
	Name            string          `json:"name"`
	Callback        json.RawMessage `json:"callback"` // Callback configuration
	DependsOn       []string        `json:"depends_on,omitempty"`
	Condition       string          `json:"condition,omitempty"`
	ContinueOnError *bool           `json:"continue_on_error,omitempty"`
	Retry           *RetryPolicy    `json:"retry,omitempty"`
}

// OriginResolver resolves an origin reference (hostname or embedded config) into
// an http.Handler that represents the full origin pipeline (transforms, policies, etc.).
// Used by MCP proxy handlers with origin_host or origin_config to route requests
// through an existing origin instead of making direct HTTP calls.
type OriginResolver func(hostname string, embeddedConfig json.RawMessage) (http.Handler, error)

// ProxyHandler executes a single HTTP request.
type ProxyHandler struct {
	URL                string            `json:"url,omitempty"`

	// OriginHost references an existing origin by hostname. The request is routed
	// through the referenced origin's full pipeline (transforms, modifiers, policies).
	// Mutually exclusive with URL and OriginConfig.
	OriginHost string `json:"origin_host,omitempty"`

	// OriginConfig embeds an inline origin configuration. The request is routed
	// through the embedded origin's full pipeline. Follows the same pattern as
	// FallbackOrigin's embedded origin field.
	// Mutually exclusive with URL and OriginHost.
	OriginConfig json.RawMessage `json:"origin_config,omitempty"`

	// resolvedOriginHandler is the resolved http.Handler for origin routing.
	// Set during initialization when OriginHost or OriginConfig is configured.
	resolvedOriginHandler http.Handler
	Method             string            `json:"method,omitempty"`
	Headers            map[string]string `json:"headers,omitempty"`
	Body               string            `json:"body,omitempty"`
	Timeout            reqctx.Duration   `json:"timeout,omitempty" validate:"max_value=1m"`
	SkipTLSVerifyHost  bool              `json:"skip_tls_verify_host,omitempty"`

	// QueryParams are structured query parameters with automatic URL encoding.
	// Values are Mustache templates. Appended to the base URL.
	QueryParams map[string]string `json:"query_params,omitempty"`

	// BodyTemplate is a structured JSON body with Mustache interpolation in string values.
	// Takes precedence over Body if both are set.
	BodyTemplate map[string]interface{} `json:"body_template,omitempty"`

	// ResponseMapping extracts and renames fields from the API response using dot-path notation.
	// Keys are output field names, values are dot-separated paths into the response JSON.
	// Example: {"name": "data.user.full_name", "email": "data.user.email"}
	ResponseMapping map[string]string `json:"response_mapping,omitempty"`

	// ErrorMapping maps HTTP status codes to user-friendly error messages.
	// Keys are status codes (e.g., "404", "5xx"). Values are Mustache templates.
	// Matched errors return as ToolResult with isError: true.
	ErrorMapping map[string]string `json:"error_mapping,omitempty"`

	// Auth configures per-tool authentication for upstream API calls.
	Auth *ToolAuthConfig `json:"auth,omitempty"`

	// Pagination configures auto-pagination for APIs that return paged results.
	Pagination *PaginationConfig `json:"pagination,omitempty"`

	// ContentType controls the response content type.
	// "text" (default), "image", "resource", "auto"
	ContentType string `json:"content_type,omitempty"`
	// MimeType for image/resource content types.
	ContentMimeType string `json:"content_mime_type,omitempty"`
}

// ToolFilter defines include/exclude glob patterns for filtering tools.
type ToolFilter struct {
	// Include patterns - only tools matching at least one pattern pass. Empty = include all.
	Include []string `json:"include,omitempty"`
	// Exclude patterns - tools matching any pattern are removed. Applied after include.
	Exclude []string `json:"exclude,omitempty"`
	// IncludeTags - only tools with at least one matching tag pass. Empty = no tag filter.
	IncludeTags []string `json:"include_tags,omitempty"`
	// ExcludeTags - tools with any matching tag are removed.
	ExcludeTags []string `json:"exclude_tags,omitempty"`
}

// ToolOverride allows overriding federated tool properties.
type ToolOverride struct {
	Rename      string           `json:"rename,omitempty"`
	Description string           `json:"description,omitempty"`
	Visibility  string           `json:"visibility,omitempty"`
	Tags        []string         `json:"tags,omitempty"`
	Annotations *ToolAnnotations `json:"annotations,omitempty"`
}

// StaticHandler returns static content.
type StaticHandler struct {
	Content string `json:"content"`
}

// RetryPolicy defines retry behavior.
type RetryPolicy struct {
	MaxAttempts  int             `json:"max_attempts,omitempty" validate:"max_value=10,default_value=3"`
	InitialDelay reqctx.Duration `json:"initial_delay,omitempty" validate:"max_value=1m,default_value=100ms"`
	MaxDelay     reqctx.Duration `json:"max_delay,omitempty" validate:"max_value=1m,default_value=10s"`
	Backoff      string          `json:"backoff,omitempty"` // "fixed", "exponential"
}

// ResourceConfig defines a resource's configuration.
type ResourceConfig struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mime_type,omitempty"`

	// Handler defines how to fetch this resource
	Handler ResourceHandler `json:"handler"`
}

// ResourceHandler defines how a resource is fetched.
type ResourceHandler struct {
	// Type: "static", "proxy", "template"
	Type string `json:"type"`

	// Static content
	Static *StaticHandler `json:"static,omitempty"`

	// Proxy to fetch dynamically
	Proxy *ProxyHandler `json:"proxy,omitempty"`
}

// ErrorHandlingConfig configures error behavior.
type ErrorHandlingConfig struct {
	// IncludeStackTrace includes stack trace in error details (dev only)
	IncludeStackTrace bool `json:"include_stack_trace,omitempty"`

	// RetryUpstreamErrors automatically retry 5xx errors
	RetryUpstreamErrors bool `json:"retry_upstream_errors,omitempty"`

	// CircuitBreaker configuration
	CircuitBreaker *CircuitBreakerConfig `json:"circuit_breaker,omitempty"`
}

// CircuitBreakerConfig configures circuit breaker behavior.
type CircuitBreakerConfig struct {
	Enabled          bool            `json:"enabled"`
	FailureThreshold int             `json:"failure_threshold,omitempty" validate:"default_value=5"`
	SuccessThreshold int             `json:"success_threshold,omitempty" validate:"default_value=2"`
	ResetTimeout     reqctx.Duration `json:"reset_timeout,omitempty" validate:"max_value=5m,default_value=30s"`
}

// =============================================================================
// Execution Context Types
// =============================================================================

// ToolExecutionContext contains context for tool execution.
type ToolExecutionContext struct {
	ToolName    string
	Arguments   map[string]interface{}
	Tool        *ToolConfig
	RequestID   interface{}
	StepResults map[string]interface{} // Results from orchestration steps
}

// HasOriginRouting returns true if the proxy handler is configured to route
// through an existing origin rather than making a direct HTTP call.
func (p *ProxyHandler) HasOriginRouting() bool {
	return p != nil && (p.OriginHost != "" || len(p.OriginConfig) > 0)
}

// HasOriginHost returns true if the proxy handler references an origin by hostname.
func (p *ProxyHandler) HasOriginHost() bool {
	return p != nil && p.OriginHost != ""
}

// HasOriginConfig returns true if the proxy handler has an embedded origin config.
func (p *ProxyHandler) HasOriginConfig() bool {
	return p != nil && len(p.OriginConfig) > 0
}
