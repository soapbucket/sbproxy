package wasm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const (
	// registryPrefix is the path prefix for registry-resolved modules.
	registryPrefix = "registry:"

	// systemPrefix is the path prefix for system workspace modules.
	systemPrefix = "system:"

	// systemWorkspaceID is the workspace ID used for system-scoped modules.
	systemWorkspaceID = "_system"
)

const (
	// PhaseRequest indicates the plugin runs during request processing.
	PhaseRequest = "request"
	// PhaseResponse indicates the plugin runs during response processing.
	PhaseResponse = "response"

	// hostModuleName is the module name used for SoapBucket host functions.
	hostModuleName = "sb"
)

// PluginConfig defines a WASM plugin configuration.
type PluginConfig struct {
	Name           string          `json:"name"`
	Path           string          `json:"path,omitempty"`         // File path, registry:name:version, or system:name
	Source         []byte          `json:"-"`                      // Or inline WASM bytes (takes precedence over Path)
	Phase          string          `json:"phase,omitempty"`        // "request" or "response" (default: "request")
	Config         json.RawMessage `json:"config,omitempty"`       // Plugin-specific configuration
	WorkspaceID    string          `json:"workspace_id,omitempty"` // Workspace scope for registry: lookups
	AllowedSecrets []string        `json:"allowed_secrets,omitempty"`
}

// Plugin represents a compiled and instantiated WASM plugin.
type Plugin struct {
	name           string
	module         WasmModule
	compiled       CompiledWasmModule
	phase          string
	config         []byte
	allowedSecrets []string
}

// Name returns the plugin name.
func (p *Plugin) Name() string {
	return p.name
}

// Phase returns the plugin phase ("request" or "response").
func (p *Plugin) Phase() string {
	return p.phase
}

// LoadPlugin compiles and instantiates a WASM module from the given configuration.
func (r *Runtime) LoadPlugin(ctx context.Context, cfg PluginConfig) (*Plugin, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.engine == nil {
		return nil, fmt.Errorf("wasm runtime is closed")
	}

	if cfg.Name == "" {
		return nil, fmt.Errorf("plugin name is required")
	}

	phase := cfg.Phase
	if phase == "" {
		phase = PhaseRequest
	}
	if phase != PhaseRequest && phase != PhaseResponse {
		return nil, fmt.Errorf("invalid plugin phase %q: must be %q or %q", phase, PhaseRequest, PhaseResponse)
	}

	// Check for registry: or system: prefix resolution
	if rm, err := r.resolveFromRegistry(ctx, cfg); rm != nil || err != nil {
		if err != nil {
			return nil, fmt.Errorf("failed to resolve WASM source for plugin %q: %w", cfg.Name, err)
		}
		// Register host functions before instantiation
		hostModule := r.engine.NewHostModuleBuilder(hostModuleName)
		RegisterHostFunctions(hostModule)
		if _, err := hostModule.Instantiate(ctx); err != nil {
			return nil, fmt.Errorf("failed to instantiate host module for plugin %q: %w", cfg.Name, err)
		}
		// Registry modules are already compiled; instantiate directly.
		moduleCfg := NewModuleConfig().WithName(cfg.Name)
		module, err := r.engine.InstantiateModule(ctx, rm.Compiled.compiled, moduleCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to instantiate WASM plugin %q: %w", cfg.Name, err)
		}
		return &Plugin{
			name:           cfg.Name,
			module:         module,
			compiled:       rm.Compiled.compiled,
			phase:          phase,
			config:         cfg.Config,
			allowedSecrets: append([]string(nil), cfg.AllowedSecrets...),
		}, nil
	}

	// Resolve WASM binary source from file or inline bytes
	wasmBytes, err := resolveSource(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve WASM source for plugin %q: %w", cfg.Name, err)
	}

	// Register host functions before instantiation
	hostModule := r.engine.NewHostModuleBuilder(hostModuleName)
	RegisterHostFunctions(hostModule)
	if _, err := hostModule.Instantiate(ctx); err != nil {
		return nil, fmt.Errorf("failed to instantiate host module for plugin %q: %w", cfg.Name, err)
	}

	// Compile the WASM module
	compiled, err := r.engine.CompileModule(ctx, wasmBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to compile WASM plugin %q: %w", cfg.Name, err)
	}

	// Instantiate with the plugin name as module name
	moduleCfg := NewModuleConfig().WithName(cfg.Name)
	module, err := r.engine.InstantiateModule(ctx, compiled, moduleCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate WASM plugin %q: %w", cfg.Name, err)
	}

	return &Plugin{
		name:           cfg.Name,
		module:         module,
		compiled:       compiled,
		phase:          phase,
		config:         cfg.Config,
		allowedSecrets: append([]string(nil), cfg.AllowedSecrets...),
	}, nil
}

// resolveFromRegistry checks if the plugin path uses a registry: or system: prefix
// and resolves the module from the registry.
func (r *Runtime) resolveFromRegistry(ctx context.Context, cfg PluginConfig) (*RegisteredModule, error) {
	path := cfg.Path

	if strings.HasPrefix(path, registryPrefix) {
		if r.registry == nil {
			return nil, fmt.Errorf("registry: prefix used but no module registry is configured")
		}
		remainder := strings.TrimPrefix(path, registryPrefix)
		parts := strings.SplitN(remainder, ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("invalid registry reference %q, expected registry:name:version", path)
		}
		workspaceID := cfg.WorkspaceID
		if workspaceID == "" {
			return nil, fmt.Errorf("registry: prefix requires a workspace_id in plugin config")
		}
		rm, err := r.registry.Get(ctx, workspaceID, parts[0], parts[1])
		if err != nil {
			return nil, fmt.Errorf("registry lookup failed for %q: %w", path, err)
		}
		return rm, nil
	}

	if strings.HasPrefix(path, systemPrefix) {
		if r.registry == nil {
			return nil, fmt.Errorf("system: prefix used but no module registry is configured")
		}
		name := strings.TrimPrefix(path, systemPrefix)
		if name == "" {
			return nil, fmt.Errorf("invalid system reference %q, expected system:name", path)
		}
		versions, err := r.registry.ListVersions(ctx, systemWorkspaceID, name)
		if err != nil {
			return nil, fmt.Errorf("failed to list system module versions for %q: %w", name, err)
		}
		if len(versions) == 0 {
			return nil, fmt.Errorf("no versions found for system module %q", name)
		}
		latestVersion := versions[len(versions)-1]
		rm, err := r.registry.Get(ctx, systemWorkspaceID, name, latestVersion)
		if err != nil {
			return nil, fmt.Errorf("registry lookup failed for system module %q version %q: %w", name, latestVersion, err)
		}
		return rm, nil
	}

	return nil, nil
}

// CallOnRequest calls the guest's sb_on_request function and returns the plugin action.
func (p *Plugin) CallOnRequest(ctx context.Context) (PluginAction, error) {
	fn := p.module.ExportedFunction("sb_on_request")
	if fn == nil {
		return ActionContinue, nil
	}

	results, err := fn.Call(ctx)
	if err != nil {
		return ActionContinue, fmt.Errorf("sb_on_request failed in plugin %q: %w", p.name, err)
	}

	if len(results) == 0 {
		return ActionContinue, nil
	}

	return PluginAction(results[0]), nil
}

// CallOnResponse calls the guest's sb_on_response function and returns the plugin action.
func (p *Plugin) CallOnResponse(ctx context.Context) (PluginAction, error) {
	fn := p.module.ExportedFunction("sb_on_response")
	if fn == nil {
		return ActionContinue, nil
	}

	results, err := fn.Call(ctx)
	if err != nil {
		return ActionContinue, fmt.Errorf("sb_on_response failed in plugin %q: %w", p.name, err)
	}

	if len(results) == 0 {
		return ActionContinue, nil
	}

	return PluginAction(results[0]), nil
}

// Close releases resources held by this plugin.
func (p *Plugin) Close(ctx context.Context) error {
	if p.module != nil {
		return p.module.Close(ctx)
	}
	return nil
}

// resolveSource returns the WASM binary bytes from the config.
func resolveSource(cfg PluginConfig) ([]byte, error) {
	if len(cfg.Source) > 0 {
		return cfg.Source, nil
	}
	if cfg.Path == "" {
		return nil, fmt.Errorf("either path or source must be provided")
	}
	data, err := os.ReadFile(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read WASM file %q: %w", cfg.Path, err)
	}
	return data, nil
}
