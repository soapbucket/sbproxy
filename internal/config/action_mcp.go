// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/extension/mcp"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func init() {
	loaderFns[TypeMCP] = LoadMCP
}

var _ ActionConfig = (*MCPAction)(nil)

// MCPAction represents an MCP (Model Context Protocol) server action.
type MCPAction struct {
	MCPActionConfig

	handler        *mcp.Handler        `json:"-"`
	gatewayHandler *mcp.GatewayHandler `json:"-"`
}

// MCPActionConfig defines the configuration for MCP server endpoints.
type MCPActionConfig struct {
	BaseAction

	// Mode: "orchestrator" (default) or "gateway"
	Mode string `json:"mode,omitempty"`

	// ServerInfo for initialize response
	ServerInfo mcp.ServerInfo `json:"server_info"`

	// Capabilities advertised to clients
	Capabilities mcp.Capabilities `json:"capabilities"`

	// Tools available on this server
	Tools []mcp.ToolConfig `json:"tools"`

	// Resources available on this server (optional)
	Resources []mcp.ResourceConfig `json:"resources,omitempty"`

	// Prompts available on this server (optional)
	Prompts []mcp.PromptConfig `json:"prompts,omitempty"`

	// FederatedServers for upstream MCP server discovery
	FederatedServers []mcp.FederatedServerConfig `json:"federated_servers,omitempty"`

	// ErrorHandling configuration
	ErrorHandling *mcp.ErrorHandlingConfig `json:"error_handling,omitempty"`

	// DefaultTimeout for tool execution
	DefaultTimeout reqctx.Duration `json:"default_timeout,omitempty" validate:"max_value=5m,default_value=30s"`

	// ToolCache configuration
	ToolCache *mcp.ToolCacheConfig `json:"tool_cache,omitempty"`
}

// LoadMCP loads an MCP action from JSON configuration.
func LoadMCP(data []byte) (ActionConfig, error) {
	var config MCPActionConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal MCP config: %w", err)
	}

	// Validate server info
	if config.ServerInfo.Name == "" {
		config.ServerInfo.Name = "mcp-server"
	}
	if config.ServerInfo.Version == "" {
		config.ServerInfo.Version = "1.0.0"
	}

	// Validate federated server configs
	for _, server := range config.FederatedServers {
		if err := mcp.ValidateServerConfig(server); err != nil {
			return nil, err
		}
	}

	// Check for circular origin references
	if err := mcp.ValidateOriginReferences(config.FederatedServers); err != nil {
		return nil, err
	}

	action := &MCPAction{
		MCPActionConfig: config,
	}

	return action, nil
}

// Init implements ActionConfig interface.
func (m *MCPAction) Init(cfg *Config) error {
	m.cfg = cfg

	// Build MCP config
	mcpConfig := &mcp.Config{
		Mode:             m.Mode,
		ServerInfo:       m.ServerInfo,
		Capabilities:     m.Capabilities,
		Tools:            m.Tools,
		Resources:        m.Resources,
		Prompts:          m.Prompts,
		FederatedServers: m.FederatedServers,
		ErrorHandling:    m.ErrorHandling,
		ToolCache:        m.ToolCache,
	}

	// Set default timeout
	if m.DefaultTimeout.Duration > 0 {
		mcpConfig.DefaultTimeout.Duration = m.DefaultTimeout.Duration
	}

	// Build OriginResolver from config loaders (set by configloader to avoid import cycles)
	if cfg.OriginConfigLoader != nil || cfg.EmbeddedConfigLoader != nil {
		mcpConfig.OriginResolver = func(hostname string, embeddedConfig json.RawMessage) (http.Handler, error) {
			if hostname != "" && cfg.OriginConfigLoader != nil {
				return cfg.OriginConfigLoader(hostname)
			}
			if len(embeddedConfig) > 0 && cfg.EmbeddedConfigLoader != nil {
				return cfg.EmbeddedConfigLoader(embeddedConfig)
			}
			return nil, fmt.Errorf("no loader available for origin resolution")
		}
	}

	// Create handler based on mode
	if m.Mode == mcp.ModeGateway {
		gatewayHandler, err := mcp.NewGatewayHandler(mcpConfig)
		if err != nil {
			return fmt.Errorf("failed to create MCP gateway handler: %w", err)
		}

		// Discover tools from upstream servers
		if err := gatewayHandler.Init(context.Background()); err != nil {
			return fmt.Errorf("failed to initialize MCP gateway: %w", err)
		}

		m.gatewayHandler = gatewayHandler
	} else {
		handler, err := mcp.NewHandler(mcpConfig)
		if err != nil {
			return fmt.Errorf("failed to create MCP handler: %w", err)
		}
		m.handler = handler
	}

	return nil
}

// GetType implements ActionConfig interface.
func (m *MCPAction) GetType() string {
	return TypeMCP
}

// Rewrite implements ActionConfig interface.
func (m *MCPAction) Rewrite() RewriteFn {
	return nil
}

// Transport implements ActionConfig interface.
func (m *MCPAction) Transport() TransportFn {
	return nil
}

// Handler implements ActionConfig interface.
func (m *MCPAction) Handler() http.Handler {
	if m.gatewayHandler != nil {
		return m.gatewayHandler
	}
	return m.handler
}

// ModifyResponse implements ActionConfig interface.
func (m *MCPAction) ModifyResponse() ModifyResponseFn {
	return nil
}

// ErrorHandler implements ActionConfig interface.
func (m *MCPAction) ErrorHandler() ErrorHandlerFn {
	return nil
}

// IsProxy implements ActionConfig interface.
func (m *MCPAction) IsProxy() bool {
	return false
}
