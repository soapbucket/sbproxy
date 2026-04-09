// Package mcp implements the Model Context Protocol (MCP) for AI tool and resource integration.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// =============================================================================
// MCP Handler
// =============================================================================

// Handler processes MCP requests in orchestrator mode.
type Handler struct {
	config         *Config
	toolRegistry   *ToolRegistry
	promptRegistry *PromptRegistry
	validator      *SchemaValidator
	errorHandler   *ErrorHandler
	executor       *ToolExecutor
	accessChecker  *AccessChecker
	toolCache      *ToolResultCache
	auditLogger    *AuditLogger
	logger         *slog.Logger
}

// NewHandler creates a new MCP handler from configuration.
func NewHandler(config *Config) (*Handler, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	// Validate proxy handler sources and build tool registry
	for _, tool := range config.Tools {
		if tool.Handler.Type == "proxy" && tool.Handler.Proxy != nil {
			if err := ValidateProxyHandlerSource(tool.Handler.Proxy); err != nil {
				return nil, fmt.Errorf("tool %s: %w", tool.Name, err)
			}
		}
	}

	registry := NewToolRegistry()
	for _, tool := range config.Tools {
		if err := registry.Register(tool); err != nil {
			return nil, fmt.Errorf("failed to register tool %s: %w", tool.Name, err)
		}
	}

	// Build schema validator
	validator, err := NewSchemaValidator(config.Tools)
	if err != nil {
		return nil, fmt.Errorf("failed to create validator: %w", err)
	}

	// Build error handler
	errorHandler := NewErrorHandler(config.ErrorHandling)

	// Build executor
	executor := NewToolExecutor(registry, validator, config)

	// Build access checker from per-tool access configs
	accessRules := make(map[string]*ToolAccessConfig)
	for _, tool := range config.Tools {
		if tool.Access != nil {
			accessRules[tool.Name] = tool.Access
		}
	}
	accessChecker := NewAccessChecker(accessRules)

	// Build prompt registry
	promptRegistry := NewPromptRegistry()
	for _, prompt := range config.Prompts {
		if err := promptRegistry.Register(prompt); err != nil {
			return nil, fmt.Errorf("failed to register prompt %s: %w", prompt.Name, err)
		}
	}

	// Build tool result cache
	var toolCache *ToolResultCache
	if config.ToolCache != nil && config.ToolCache.Enabled {
		toolCache = NewToolResultCache(config.ToolCache)
	}

	// Resolve origin handlers for proxy tools with origin_host or origin_config
	if config.OriginResolver != nil {
		for i := range config.Tools {
			tool := &config.Tools[i]
			if tool.Handler.Type == "proxy" && tool.Handler.Proxy != nil && tool.Handler.Proxy.HasOriginRouting() {
				handler, err := config.OriginResolver(tool.Handler.Proxy.OriginHost, tool.Handler.Proxy.OriginConfig)
				if err != nil {
					return nil, fmt.Errorf("tool %s: failed to resolve origin handler: %w", tool.Name, err)
				}
				tool.Handler.Proxy.resolvedOriginHandler = handler
			}
		}
	}

	return &Handler{
		config:         config,
		toolRegistry:   registry,
		promptRegistry: promptRegistry,
		validator:      validator,
		errorHandler:   errorHandler,
		executor:       executor,
		accessChecker:  accessChecker,
		toolCache:      toolCache,
		auditLogger:    NewAuditLogger(slog.Default()),
		logger:         slog.Default(),
	}, nil
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeError(w, nil, NewParseError("failed to read request body"))
		return
	}
	defer r.Body.Close()

	// Parse JSON-RPC request
	req, parseErr := ParseJSONRPCRequest(body)
	if parseErr != nil {
		h.writeError(w, nil, parseErr)
		return
	}

	// Validate request structure
	if validErr := req.Validate(); validErr != nil {
		h.writeError(w, req.ID, validErr)
		return
	}

	// Log request and record metrics
	h.logger.Debug("mcp request",
		"method", req.Method,
		"id", req.ID,
	)
	reqStart := time.Now()
	defer func() {
		RecordRequest(req.Method, time.Since(reqStart).Seconds())
	}()

	// Route to appropriate handler
	var response *JSONRPCResponse
	switch req.Method {
	case "initialize":
		response = h.handleInitialize(ctx, req)
	case "initialized":
		// Notification - no response needed
		response = nil
	case "tools/list":
		response = h.handleToolsList(ctx, req)
	case "tools/call":
		response = h.handleToolsCall(ctx, req)
	case "resources/list":
		response = h.handleResourcesList(ctx, req)
	case "resources/read":
		response = h.handleResourcesRead(ctx, req)
	case "prompts/list":
		response = h.handlePromptsList(ctx, req)
	case "prompts/get":
		response = h.handlePromptsGet(ctx, req)
	case "logging/setLevel":
		response = h.handleLoggingSetLevel(ctx, req)
	case "completion/complete":
		response = h.handleCompletion(ctx, req)
	case "roots/list":
		response = h.handleRootsList(ctx, req)
	case "notifications/roots/list_changed":
		response = nil // Notification, no response
	case "ping":
		response = h.handlePing(ctx, req)
	default:
		h.writeError(w, req.ID, NewMethodNotFoundError(req.Method))
		return
	}

	// Don't respond to notifications
	if req.IsNotification() {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if response != nil {
		h.writeResponse(w, response)
	}
}

// =============================================================================
// Method Handlers
// =============================================================================

func (h *Handler) handleInitialize(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	// Parse params (optional)
	params, err := req.ParseInitializeParams()
	if err != nil {
		return h.errorHandler.HandleError(req.ID, err)
	}

	h.logger.Info("mcp initialize",
		"client_name", params.ClientInfo.Name,
		"client_version", params.ClientInfo.Version,
		"protocol_version", params.ProtocolVersion,
	)

	return NewSuccessResponse(req.ID, &InitializeResult{
		ProtocolVersion: ProtocolVersion,
		Capabilities:    h.config.Capabilities,
		ServerInfo:      h.config.ServerInfo,
	})
}

func (h *Handler) handleToolsList(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	allTools := h.toolRegistry.List()

	// Extract identity from context for access filtering
	roles, keyID := extractIdentity(ctx)

	// Filter tools by access control
	var tools []Tool
	for _, tool := range allTools {
		if err := h.accessChecker.Check(tool.Name, roles, keyID); err == nil {
			tools = append(tools, tool)
		}
	}
	if tools == nil {
		tools = []Tool{}
	}

	return NewSuccessResponse(req.ID, &ListToolsResult{
		Tools: tools,
	})
}

func (h *Handler) handleToolsCall(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	// Parse tool call params
	params, err := req.ParseToolCallParams()
	if err != nil {
		return h.errorHandler.HandleError(req.ID, err)
	}

	h.logger.Debug("mcp tools/call",
		"tool", params.Name,
		"arguments", params.Arguments,
	)

	// Check access control - return "tool not found" to avoid information leakage
	roles, keyID := extractIdentity(ctx)
	if err := h.accessChecker.Check(params.Name, roles, keyID); err != nil {
		RecordAccessDenied(params.Name)
		return h.errorHandler.HandleError(req.ID, NewToolNotFoundError(params.Name))
	}

	start := time.Now()

	// Check cache
	var cacheKey string
	toolCfg, _ := h.toolRegistry.Get(params.Name)
	if h.toolCache != nil && toolCfg != nil && toolCfg.Cache != nil {
		cacheKey = BuildCacheKey(ctx, params.Name, params.Arguments, toolCfg.Cache)
		if cached, ok := h.toolCache.Get(cacheKey); ok {
			elapsed := time.Since(start)
			RecordToolCall(params.Name, "success", elapsed.Seconds())
			RecordToolCacheHit(params.Name)
			h.auditLogger.LogToolCall(AuditEntry{
				ToolName: params.Name, Roles: roles, KeyID: keyID,
				IsError: false, Latency: elapsed, Cached: true,
			})
			return NewSuccessResponse(req.ID, cached)
		}
		RecordToolCacheMiss(params.Name)
	}

	// Execute tool
	result, execErr := h.executor.Execute(ctx, params.Name, params.Arguments)
	if execErr != nil {
		elapsed := time.Since(start)
		RecordToolCall(params.Name, "error", elapsed.Seconds())
		RecordToolError(params.Name, execErr.Type.String())
		h.auditLogger.LogToolCall(AuditEntry{
			ToolName: params.Name, Roles: roles, KeyID: keyID,
			IsError: true, Latency: elapsed,
		})
		return h.errorHandler.HandleError(req.ID, execErr)
	}

	elapsed := time.Since(start)
	RecordToolCall(params.Name, "success", elapsed.Seconds())
	h.auditLogger.LogToolCall(AuditEntry{
		ToolName: params.Name, Roles: roles, KeyID: keyID,
		IsError: false, Latency: elapsed,
	})

	// Store in cache
	if cacheKey != "" && toolCfg.Cache != nil {
		h.toolCache.Put(cacheKey, result, toolCfg.Cache.TTL.Duration)
	}

	return NewSuccessResponse(req.ID, result)
}

// extractIdentity extracts roles and key ID from the request context.
// These are set by upstream auth middleware (JWT, API key, etc.).
func extractIdentity(ctx context.Context) (roles []string, keyID string) {
	if v := ctx.Value(ctxKeyRoles); v != nil {
		if r, ok := v.([]string); ok {
			roles = r
		}
	}
	if v := ctx.Value(ctxKeyKeyID); v != nil {
		if k, ok := v.(string); ok {
			keyID = k
		}
	}
	return roles, keyID
}

// Context keys for MCP identity propagation.
type mcpContextKey string

const (
	ctxKeyRoles mcpContextKey = "mcp_roles"
	ctxKeyKeyID mcpContextKey = "mcp_key_id"
)

// ContextWithIdentity returns a new context with MCP identity information.
// This is used by auth middleware to pass identity into the MCP handler.
func ContextWithIdentity(ctx context.Context, roles []string, keyID string) context.Context {
	if len(roles) > 0 {
		ctx = context.WithValue(ctx, ctxKeyRoles, roles)
	}
	if keyID != "" {
		ctx = context.WithValue(ctx, ctxKeyKeyID, keyID)
	}
	return ctx
}

func (h *Handler) handleResourcesList(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	// Build resource list from config
	resources := make([]Resource, len(h.config.Resources))
	for i, res := range h.config.Resources {
		resources[i] = Resource{
			URI:         res.URI,
			Name:        res.Name,
			Description: res.Description,
			MimeType:    res.MimeType,
		}
	}

	return NewSuccessResponse(req.ID, &ListResourcesResult{
		Resources: resources,
	})
}

func (h *Handler) handleResourcesRead(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	// Parse params
	params, err := req.ParseReadResourceParams()
	if err != nil {
		return h.errorHandler.HandleError(req.ID, err)
	}

	// Find resource
	var resource *ResourceConfig
	for i := range h.config.Resources {
		if h.config.Resources[i].URI == params.URI {
			resource = &h.config.Resources[i]
			break
		}
	}

	if resource == nil {
		return h.errorHandler.HandleError(req.ID, NewProtocolError(
			CodeInvalidParams,
			fmt.Sprintf("resource not found: %s", params.URI),
			nil,
		))
	}

	// Execute resource handler
	content, execErr := h.executeResourceHandler(ctx, resource)
	if execErr != nil {
		return h.errorHandler.HandleError(req.ID, execErr)
	}

	return NewSuccessResponse(req.ID, &ReadResourceResult{
		Contents: []ResourceContent{
			{
				URI:      resource.URI,
				MimeType: resource.MimeType,
				Text:     content,
			},
		},
	})
}

func (h *Handler) handlePing(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	return NewSuccessResponse(req.ID, map[string]interface{}{})
}

// =============================================================================
// Prompts Handlers
// =============================================================================

func (h *Handler) handlePromptsList(_ context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	prompts := h.promptRegistry.List()
	return NewSuccessResponse(req.ID, &ListPromptsResult{Prompts: prompts})
}

func (h *Handler) handlePromptsGet(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	params, err := req.ParseGetPromptParams()
	if err != nil {
		return h.errorHandler.HandleError(req.ID, err)
	}

	prompt, getErr := h.promptRegistry.Get(params.Name)
	if getErr != nil {
		return h.errorHandler.HandleError(req.ID, NewProtocolError(
			CodeInvalidParams,
			fmt.Sprintf("prompt not found: %s", params.Name),
			nil,
		))
	}

	result, renderErr := RenderPrompt(ctx, prompt, params.Arguments)
	if renderErr != nil {
		return h.errorHandler.HandleError(req.ID, NewInternalError(renderErr.Error(), renderErr))
	}

	RecordPromptRender(params.Name)
	return NewSuccessResponse(req.ID, result)
}

// =============================================================================
// Logging Handler
// =============================================================================

func (h *Handler) handleLoggingSetLevel(_ context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	if req.Params == nil {
		return NewSuccessResponse(req.ID, map[string]interface{}{})
	}

	var params struct {
		Level string `json:"level"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return h.errorHandler.HandleError(req.ID, NewProtocolError(
			CodeInvalidParams, "invalid logging params", err.Error(),
		))
	}

	// Validate and store log level
	switch params.Level {
	case "debug", "info", "warning", "error", "critical", "alert", "emergency":
		h.config.LogLevel = params.Level
		h.logger.Info("mcp log level changed", "level", params.Level)
	default:
		return h.errorHandler.HandleError(req.ID, NewProtocolError(
			CodeInvalidParams,
			fmt.Sprintf("invalid log level: %s", params.Level),
			nil,
		))
	}

	return NewSuccessResponse(req.ID, map[string]interface{}{})
}

// =============================================================================
// Completion Handler
// =============================================================================

func (h *Handler) handleCompletion(_ context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	params, err := req.ParseCompletionParams()
	if err != nil {
		return h.errorHandler.HandleError(req.ID, err)
	}

	RecordCompletionRequest(params.Ref.Type)

	var result *CompletionResult

	switch params.Ref.Type {
	case "ref/prompt":
		result = CompletePromptArgument(h.promptRegistry, params.Ref.Name, params.Argument.Name, params.Argument.Value)
	case "ref/resource":
		result = CompleteResourceURI(h.config.Resources, params.Argument.Value)
	default:
		return h.errorHandler.HandleError(req.ID, NewProtocolError(
			CodeInvalidParams, fmt.Sprintf("unsupported ref type: %s", params.Ref.Type), nil,
		))
	}

	return NewSuccessResponse(req.ID, result)
}

// =============================================================================
// ExecuteTool - Direct Tool Execution (for in-process forwarding)
// =============================================================================

// ExecuteTool executes a tool by name with the given arguments, bypassing HTTP.
// Used for in-process tool call forwarding when upstream is an internal origin.
func (h *Handler) ExecuteTool(ctx context.Context, name string, args map[string]interface{}) (*ToolResult, *MCPError) {
	return h.executor.Execute(ctx, name, args)
}

// =============================================================================
// Roots Handler
// =============================================================================

func (h *Handler) handleRootsList(_ context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	// Roots are not applicable for remote HTTP-based MCP servers.
	// Return empty list per spec.
	return NewSuccessResponse(req.ID, map[string]interface{}{
		"roots": []interface{}{},
	})
}

// =============================================================================
// Resource Handler Execution
// =============================================================================

func (h *Handler) executeResourceHandler(ctx context.Context, resource *ResourceConfig) (string, *MCPError) {
	switch resource.Handler.Type {
	case "static":
		if resource.Handler.Static == nil {
			return "", NewInternalError("static handler not configured", nil)
		}
		return resource.Handler.Static.Content, nil

	case "proxy":
		if resource.Handler.Proxy == nil {
			return "", NewInternalError("proxy handler not configured", nil)
		}
		// Execute proxy request
		req, err := http.NewRequestWithContext(ctx, "GET", resource.Handler.Proxy.URL, nil)
		if err != nil {
			return "", NewInternalError("failed to create request", err)
		}

		for key, value := range resource.Handler.Proxy.Headers {
			req.Header.Set(key, value)
		}

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return "", NewUpstreamError("resource", resource.URI, 0, "", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", NewInternalError("failed to read response", err)
		}

		if resp.StatusCode >= 400 {
			return "", NewUpstreamError("resource", resource.URI, resp.StatusCode, string(body), nil)
		}

		return string(body), nil

	default:
		return "", NewInternalError(fmt.Sprintf("unknown resource handler type: %s", resource.Handler.Type), nil)
	}
}

// =============================================================================
// Response Helpers
// =============================================================================

func (h *Handler) writeResponse(w http.ResponseWriter, resp *JSONRPCResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // Always 200 for JSON-RPC

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger.Error("failed to write response", "error", err)
	}
}

func (h *Handler) writeError(w http.ResponseWriter, id interface{}, err *MCPError) {
	resp := h.errorHandler.HandleError(id, err)
	h.writeResponse(w, resp)
}

// =============================================================================
// Utility Functions
// =============================================================================

// GetConfig returns the handler's configuration.
func (h *Handler) GetConfig() *Config {
	return h.config
}

// GetToolRegistry returns the handler's tool registry.
func (h *Handler) GetToolRegistry() *ToolRegistry {
	return h.toolRegistry
}
