// gateway.go proxies MCP requests to upstream servers with access control and tool aggregation.
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

// GatewayHandler proxies MCP requests to upstream MCP servers.
// It aggregates tools from all configured upstream servers, applies
// access control and filtering, and forwards tool calls to the correct upstream.
type GatewayHandler struct {
	config        *Config
	federation    *Federation
	accessChecker *AccessChecker
	errorHandler  *ErrorHandler
	httpClient    *http.Client
	logger        *slog.Logger
}

// NewGatewayHandler creates a new gateway handler from configuration.
func NewGatewayHandler(config *Config) (*GatewayHandler, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	if len(config.FederatedServers) == 0 {
		return nil, fmt.Errorf("gateway mode requires at least one federated_server")
	}

	timeout := 30 * time.Second
	if config.DefaultTimeout.Duration > 0 {
		timeout = config.DefaultTimeout.Duration
	}

	// Build federation for tool discovery
	federation := NewFederation(config.FederatedServers)

	// Build access checker from tool-level access configs
	accessRules := make(map[string]*ToolAccessConfig)
	for _, tool := range config.Tools {
		if tool.Access != nil {
			accessRules[tool.Name] = tool.Access
		}
	}

	return &GatewayHandler{
		config:        config,
		federation:    federation,
		accessChecker: NewAccessChecker(accessRules),
		errorHandler:  NewErrorHandler(config.ErrorHandling),
		httpClient:    &http.Client{Timeout: timeout},
		logger:        slog.Default(),
	}, nil
}

// Init performs initial tool discovery from upstream servers.
func (g *GatewayHandler) Init(ctx context.Context) error {
	return g.federation.DiscoverTools(ctx)
}

// ServeHTTP implements http.Handler for gateway mode.
func (g *GatewayHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		g.writeError(w, nil, NewParseError("failed to read request body"))
		return
	}
	defer r.Body.Close()

	req, parseErr := ParseJSONRPCRequest(body)
	if parseErr != nil {
		g.writeError(w, nil, parseErr)
		return
	}

	if validErr := req.Validate(); validErr != nil {
		g.writeError(w, req.ID, validErr)
		return
	}

	reqStart := time.Now()
	defer func() {
		RecordRequest(req.Method, time.Since(reqStart).Seconds())
	}()

	var response *JSONRPCResponse
	switch req.Method {
	case "initialize":
		response = g.handleInitialize(ctx, req)
	case "initialized":
		response = nil
	case "tools/list":
		response = g.handleToolsList(ctx, req)
	case "tools/call":
		response = g.handleToolsCall(ctx, req)
	case "ping":
		response = NewSuccessResponse(req.ID, map[string]interface{}{})
	default:
		RecordProtocolError(strconv.Itoa(CodeMethodNotFound))
		g.writeError(w, req.ID, NewMethodNotFoundError(req.Method))
		return
	}

	if req.IsNotification() {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if response != nil {
		g.writeResponse(w, response)
	}
}

func (g *GatewayHandler) handleInitialize(_ context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	return NewSuccessResponse(req.ID, &InitializeResult{
		ProtocolVersion: ProtocolVersion,
		Capabilities:    g.config.Capabilities,
		ServerInfo:      g.config.ServerInfo,
	})
}

func (g *GatewayHandler) handleToolsList(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	fedTools := g.federation.ListTools()
	roles, keyID := extractIdentity(ctx)

	var tools []Tool
	for _, ft := range fedTools {
		var tool Tool
		if err := json.Unmarshal(ft.Definition, &tool); err != nil {
			continue
		}
		// Use the resolved name (with prefix/rename applied)
		tool.Name = ft.Name

		// Access check
		if err := g.accessChecker.Check(tool.Name, roles, keyID); err != nil {
			continue
		}

		tools = append(tools, tool)
	}
	if tools == nil {
		tools = []Tool{}
	}

	return NewSuccessResponse(req.ID, &ListToolsResult{Tools: tools})
}

func (g *GatewayHandler) handleToolsCall(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	params, err := req.ParseToolCallParams()
	if err != nil {
		return g.errorHandler.HandleError(req.ID, err)
	}

	// Access check
	roles, keyID := extractIdentity(ctx)
	if err := g.accessChecker.Check(params.Name, roles, keyID); err != nil {
		RecordAccessDenied(params.Name)
		return g.errorHandler.HandleError(req.ID, NewToolNotFoundError(params.Name))
	}

	// Find the upstream server for this tool
	ft, ok := g.federation.GetTool(params.Name)
	if !ok {
		return g.errorHandler.HandleError(req.ID, NewToolNotFoundError(params.Name))
	}

	// Forward the tools/call request to the upstream server
	start := time.Now()
	result, fwdErr := g.forwardToolCall(ctx, ft, params)
	elapsed := time.Since(start)

	if fwdErr != nil {
		RecordGatewayUpstream(ft.Server, "error", elapsed.Seconds())
		RecordToolCall(params.Name, "error", elapsed.Seconds())
		return g.errorHandler.HandleError(req.ID, fwdErr)
	}

	RecordGatewayUpstream(ft.Server, "success", elapsed.Seconds())
	RecordToolCall(params.Name, "success", elapsed.Seconds())
	return NewSuccessResponse(req.ID, result)
}

// forwardToolCall sends a tools/call JSON-RPC request to the upstream MCP server.
func (g *GatewayHandler) forwardToolCall(ctx context.Context, ft *FederatedTool, params *ToolCallParams) (*ToolResult, *MCPError) {
	// Build the JSON-RPC request to forward
	// Use the original tool name (before prefix/rename) for the upstream
	fwdReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
	}

	fwdParams := ToolCallParams{
		Name:      ft.Name, // Use the federated tool's resolved name
		Arguments: params.Arguments,
	}
	paramsBytes, err := json.Marshal(fwdParams)
	if err != nil {
		return nil, NewInternalError("failed to marshal forward params", err)
	}
	fwdReq.Params = paramsBytes

	reqBody, err := json.Marshal(fwdReq)
	if err != nil {
		return nil, NewInternalError("failed to marshal forward request", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", ft.Server, bytes.NewReader(reqBody))
	if err != nil {
		return nil, NewInternalError("failed to create forward request", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := g.httpClient.Do(httpReq)
	if err != nil {
		return nil, NewUpstreamError(params.Name, "", 0, "", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, NewInternalError("failed to read upstream response", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, NewUpstreamError(params.Name, "", resp.StatusCode, string(respBody), nil)
	}

	// Parse the upstream JSON-RPC response
	var rpcResp struct {
		Result *ToolResult   `json:"result"`
		Error  *JSONRPCError `json:"error"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, NewInternalError("failed to parse upstream response", err)
	}

	if rpcResp.Error != nil {
		return nil, NewProtocolError(rpcResp.Error.Code, rpcResp.Error.Message, rpcResp.Error.Data)
	}

	if rpcResp.Result == nil {
		return &ToolResult{
			Content: []Content{{Type: "text", Text: ""}},
		}, nil
	}

	return rpcResp.Result, nil
}

func (g *GatewayHandler) writeResponse(w http.ResponseWriter, resp *JSONRPCResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (g *GatewayHandler) writeError(w http.ResponseWriter, id interface{}, err *MCPError) {
	resp := g.errorHandler.HandleError(id, err)
	g.writeResponse(w, resp)
}
