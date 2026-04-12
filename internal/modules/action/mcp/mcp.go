// Package mcp implements the Model Context Protocol (MCP) action as a self-contained leaf module.
//
// It registers itself into the pkg/plugin registry via init() under the name "mcp".
// The action handles MCP protocol requests in orchestrator or gateway mode, delegating
// to the internal/extension/mcp package for the protocol implementation.
//
// Origin resolution (OriginConfigLoader / EmbeddedConfigLoader) is provided at runtime
// via the plugin.ServiceProvider directly:
//
//	handler, _ := ctx.Services.ResolveOriginHandler("api.example.com")
//
// This package replaces the adapter-wrapped mcp in internal/modules/action/actions.go.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/extension/mcp"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterAction("mcp", New)
}

// Handler is the MCP action handler.
type Handler struct {
	cfg            Config
	handler        *mcp.Handler
	gatewayHandler *mcp.GatewayHandler
}

// New is the ActionFactory for the mcp module.
func New(raw json.RawMessage) (plugin.ActionHandler, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("mcp: parse config: %w", err)
	}

	if cfg.ServerInfo.Name == "" {
		cfg.ServerInfo.Name = "mcp-server"
	}
	if cfg.ServerInfo.Version == "" {
		cfg.ServerInfo.Version = "1.0.0"
	}

	// Validate federated server configs.
	for _, server := range cfg.FederatedServers {
		if err := mcp.ValidateServerConfig(server); err != nil {
			return nil, err
		}
	}

	if err := mcp.ValidateOriginReferences(cfg.FederatedServers); err != nil {
		return nil, err
	}

	return &Handler{cfg: cfg}, nil
}

// Type returns the action type name.
func (h *Handler) Type() string { return "mcp" }

// Provision implements plugin.Provisioner - called after New with the full PluginContext.
// It wires the OriginResolver from the ServiceProvider and creates the MCP handler.
func (h *Handler) Provision(ctx plugin.PluginContext) error {
	mcpConfig := &mcp.Config{
		Mode:             h.cfg.Mode,
		ServerInfo:       h.cfg.ServerInfo,
		Capabilities:     h.cfg.Capabilities,
		Tools:            h.cfg.Tools,
		Resources:        h.cfg.Resources,
		Prompts:          h.cfg.Prompts,
		FederatedServers: h.cfg.FederatedServers,
		ErrorHandling:    h.cfg.ErrorHandling,
		ToolCache:        h.cfg.ToolCache,
	}

	if h.cfg.DefaultTimeout.Duration > 0 {
		mcpConfig.DefaultTimeout.Duration = h.cfg.DefaultTimeout.Duration
	}

	// Wire OriginResolver from ServiceProvider.
	if ctx.Services != nil {
		services := ctx.Services
		mcpConfig.OriginResolver = func(hostname string, embeddedCfg json.RawMessage) (http.Handler, error) {
			if hostname != "" {
				return services.ResolveOriginHandler(hostname)
			}
			if len(embeddedCfg) > 0 {
				return services.ResolveEmbeddedOriginHandler(embeddedCfg)
			}
			return nil, fmt.Errorf("no loader available for origin resolution")
		}
	}

	// Create handler based on mode.
	if h.cfg.Mode == mcp.ModeGateway {
		gw, err := mcp.NewGatewayHandler(mcpConfig)
		if err != nil {
			return fmt.Errorf("mcp: failed to create gateway handler: %w", err)
		}
		if err := gw.Init(context.Background()); err != nil {
			return fmt.Errorf("mcp: failed to initialize gateway: %w", err)
		}
		h.gatewayHandler = gw
	} else {
		handler, err := mcp.NewHandler(mcpConfig)
		if err != nil {
			return fmt.Errorf("mcp: failed to create handler: %w", err)
		}
		h.handler = handler
	}

	return nil
}

// ServeHTTP serves MCP requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.gatewayHandler != nil {
		h.gatewayHandler.ServeHTTP(w, r)
		return
	}
	if h.handler != nil {
		h.handler.ServeHTTP(w, r)
		return
	}
	http.Error(w, "mcp: handler not initialized", http.StatusInternalServerError)
}
