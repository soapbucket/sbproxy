// config.go defines the configuration struct for the MCP action.
package mcp

import (
	"github.com/soapbucket/sbproxy/internal/extension/mcp"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// Config holds the full configuration for the mcp action.
type Config struct {
	// Mode: "orchestrator" (default) or "gateway".
	Mode string `json:"mode,omitempty"`

	// ServerInfo for initialize response.
	ServerInfo mcp.ServerInfo `json:"server_info"`

	// Capabilities advertised to clients.
	Capabilities mcp.Capabilities `json:"capabilities"`

	// Tools available on this server.
	Tools []mcp.ToolConfig `json:"tools"`

	// Resources available on this server (optional).
	Resources []mcp.ResourceConfig `json:"resources,omitempty"`

	// Prompts available on this server (optional).
	Prompts []mcp.PromptConfig `json:"prompts,omitempty"`

	// FederatedServers for upstream MCP server discovery.
	FederatedServers []mcp.FederatedServerConfig `json:"federated_servers,omitempty"`

	// ErrorHandling configuration.
	ErrorHandling *mcp.ErrorHandlingConfig `json:"error_handling,omitempty"`

	// DefaultTimeout for tool execution.
	DefaultTimeout reqctx.Duration `json:"default_timeout,omitempty"`

	// ToolCache configuration.
	ToolCache *mcp.ToolCacheConfig `json:"tool_cache,omitempty"`
}
