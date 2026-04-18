// mcp_federation.go implements MCP server federation using client transports.
// It aggregates tools from multiple upstream MCP servers, allowing the proxy
// to present a unified tool catalog and route tool calls to the correct server.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// ClientFederationConfig configures MCP client-side server federation.
type ClientFederationConfig struct {
	Servers []ClientMCPServerConfig `json:"servers" yaml:"servers"`
}

// ClientMCPServerConfig configures an upstream MCP server for client federation.
type ClientMCPServerConfig struct {
	Name      string            `json:"name" yaml:"name"`
	URL       string            `json:"url" yaml:"url"`
	Transport string            `json:"transport,omitempty" yaml:"transport"` // "streamable_http" (default) or "sse"
	Headers   map[string]string `json:"headers,omitempty" yaml:"headers"`
}

// ClientFederatedTool represents a tool from a federated MCP server.
type ClientFederatedTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
	ServerName  string          `json:"server_name"` // which server provides this tool
}

// ClientFederation aggregates tools from multiple upstream MCP servers using
// client-side transports (Streamable HTTP or SSE).
type ClientFederation struct {
	mu      sync.RWMutex
	servers map[string]*StreamableHTTPClient
	tools   []ClientFederatedTool
	toolMap map[string]string // tool name -> server name
}

// NewClientFederation creates a new client federation from configuration.
// All servers use the Streamable HTTP transport by default.
func NewClientFederation(cfg ClientFederationConfig) *ClientFederation {
	servers := make(map[string]*StreamableHTTPClient, len(cfg.Servers))

	for _, srv := range cfg.Servers {
		transport := NewStreamableHTTPClient(StreamableHTTPClientConfig{
			URL:     srv.URL,
			Headers: srv.Headers,
		})
		servers[srv.Name] = transport
	}

	return &ClientFederation{
		servers: servers,
		toolMap: make(map[string]string),
	}
}

// DiscoverTools queries all servers for their available tools.
// It sends tools/list to each server concurrently and aggregates the results.
func (f *ClientFederation) DiscoverTools(ctx context.Context) ([]ClientFederatedTool, error) {
	type result struct {
		tools []ClientFederatedTool
		err   error
	}

	results := make(map[string]*result)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for name, transport := range f.servers {
		wg.Add(1)
		go func(serverName string, t *StreamableHTTPClient) {
			defer wg.Done()

			resp, err := t.Send(ctx, "tools/list", nil)
			if err != nil {
				mu.Lock()
				results[serverName] = &result{err: err}
				mu.Unlock()
				return
			}

			var toolsResult struct {
				Tools []struct {
					Name        string          `json:"name"`
					Description string          `json:"description,omitempty"`
					InputSchema json.RawMessage `json:"inputSchema,omitempty"`
				} `json:"tools"`
			}

			if err := json.Unmarshal(resp, &toolsResult); err != nil {
				mu.Lock()
				results[serverName] = &result{err: fmt.Errorf("failed to parse tools from %s: %w", serverName, err)}
				mu.Unlock()
				return
			}

			var discovered []ClientFederatedTool
			for _, tool := range toolsResult.Tools {
				discovered = append(discovered, ClientFederatedTool{
					Name:        tool.Name,
					Description: tool.Description,
					InputSchema: tool.InputSchema,
					ServerName:  serverName,
				})
			}

			mu.Lock()
			results[serverName] = &result{tools: discovered}
			mu.Unlock()
		}(name, transport)
	}

	wg.Wait()

	// Collect results
	var allTools []ClientFederatedTool
	toolMap := make(map[string]string)

	for serverName, r := range results {
		if r.err != nil {
			return nil, fmt.Errorf("federation: discovery failed for server %q: %w", serverName, r.err)
		}
		for _, tool := range r.tools {
			allTools = append(allTools, tool)
			toolMap[tool.Name] = serverName
		}
	}

	f.mu.Lock()
	f.tools = allTools
	f.toolMap = toolMap
	f.mu.Unlock()

	return allTools, nil
}

// CallTool routes a tool call to the appropriate server.
func (f *ClientFederation) CallTool(ctx context.Context, toolName string, args json.RawMessage) (json.RawMessage, error) {
	f.mu.RLock()
	serverName, ok := f.toolMap[toolName]
	f.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("federation: tool %q not found in any server", toolName)
	}

	transport, ok := f.servers[serverName]
	if !ok {
		return nil, fmt.Errorf("federation: server %q not found", serverName)
	}

	params := map[string]interface{}{
		"name": toolName,
	}
	if args != nil {
		var arguments interface{}
		if err := json.Unmarshal(args, &arguments); err == nil {
			params["arguments"] = arguments
		}
	}

	return transport.Send(ctx, "tools/call", params)
}

// ListTools returns all discovered tools across all servers.
func (f *ClientFederation) ListTools() []ClientFederatedTool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	result := make([]ClientFederatedTool, len(f.tools))
	copy(result, f.tools)
	return result
}

// ServerCount returns the number of configured servers.
func (f *ClientFederation) ServerCount() int {
	return len(f.servers)
}
