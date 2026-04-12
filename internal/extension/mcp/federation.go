// Package mcp implements the Model Context Protocol (MCP) for AI tool and resource integration.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// FederatedServerConfig configures an upstream MCP server.
type FederatedServerConfig struct {
	// URL of the upstream MCP server. One of url, origin, or origin_config is required.
	URL string `json:"url,omitempty"`

	// Origin is a hostname reference to another origin in the proxy config.
	// The referenced origin must be an MCP action. Uses the config loader's
	// getConfigByHostname() for resolution.
	Origin string `json:"origin,omitempty"`

	// OriginConfig is an embedded inline origin config (like forward rules Mode B).
	OriginConfig json.RawMessage `json:"origin_config,omitempty"`

	Prefix      string `json:"prefix,omitempty"` // Namespace prefix for tools
	HealthCheck bool   `json:"health_check,omitempty"`
	Timeout     string `json:"timeout,omitempty"` // Default "30s"

	// ToolFilter filters discovered tools by glob patterns.
	ToolFilter *ToolFilter `json:"tool_filter,omitempty"`

	// ToolOverrides allows overriding properties on specific tools by original name.
	ToolOverrides map[string]*ToolOverride `json:"tool_overrides,omitempty"`
}

// HasOriginRef returns true if this server references another origin by hostname.
func (f *FederatedServerConfig) HasOriginRef() bool {
	return f.Origin != ""
}

// HasEmbeddedOrigin returns true if this server has an embedded origin config.
func (f *FederatedServerConfig) HasEmbeddedOrigin() bool {
	return len(f.OriginConfig) > 0
}

// Federation manages connections to upstream MCP servers.
type Federation struct {
	servers []FederatedServerConfig
	tools   map[string]*FederatedTool // prefix_toolName -> tool
	mu      sync.RWMutex
}

// FederatedTool wraps a tool discovered from an upstream server.
type FederatedTool struct {
	Name       string          // Original tool name
	Server     string          // Server URL
	Prefix     string          // Namespace prefix
	Definition json.RawMessage // Tool definition from upstream
}

// QualifiedName returns the tool name. The name is resolved during discovery
// (applying overrides and prefixes), so this returns the final name directly.
func (ft *FederatedTool) QualifiedName() string {
	return ft.Name
}

// NewFederation creates a new Federation from server configurations.
func NewFederation(servers []FederatedServerConfig) *Federation {
	return &Federation{
		servers: servers,
		tools:   make(map[string]*FederatedTool),
	}
}

// DiscoverTools connects to all configured servers and discovers their tools.
func (f *Federation) DiscoverTools(ctx context.Context) error {
	discovered := make(map[string]*FederatedTool)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var firstErr error

	for _, server := range f.servers {
		wg.Add(1)
		go func(srv FederatedServerConfig) {
			defer wg.Done()

			tools, err := f.discoverFromServer(ctx, srv)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("discovery failed for %s: %w", srv.URL, err)
				}
				mu.Unlock()
				return
			}

			mu.Lock()
			for _, tool := range tools {
				discovered[tool.QualifiedName()] = tool
			}
			mu.Unlock()
		}(server)
	}

	wg.Wait()

	if firstErr != nil {
		return firstErr
	}

	f.mu.Lock()
	f.tools = discovered
	f.mu.Unlock()

	return nil
}

// discoverFromServer queries a single upstream MCP server for its tools.
func (f *Federation) discoverFromServer(ctx context.Context, server FederatedServerConfig) ([]*FederatedTool, error) {
	timeout := 30 * time.Second
	if server.Timeout != "" {
		parsed, err := time.ParseDuration(server.Timeout)
		if err != nil {
			return nil, fmt.Errorf("invalid timeout %q: %w", server.Timeout, err)
		}
		timeout = parsed
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Build the tools/list JSON-RPC request
	rpcReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/list",
	}

	reqBody, err := json.Marshal(rpcReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", server.URL, io.NopCloser(
		jsonReader(reqBody),
	))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, server.URL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse JSON-RPC response
	var rpcResp struct {
		Result *ListToolsResult `json:"result"`
		Error  *JSONRPCError    `json:"error"`
	}
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("server error: %s", rpcResp.Error.Message)
	}

	if rpcResp.Result == nil {
		return nil, fmt.Errorf("empty result from server")
	}

	// Convert to federated tools, applying filter and overrides
	var tools []*FederatedTool
	for _, tool := range rpcResp.Result.Tools {
		// Apply tool filter if configured
		if server.ToolFilter != nil {
			if !matchesToolFilter(tool.Name, nil, server.ToolFilter) {
				continue
			}
		}

		// Apply overrides if configured
		if override, ok := server.ToolOverrides[tool.Name]; ok {
			if override.Visibility == VisibilityDisabled {
				continue
			}
			if override.Description != "" {
				tool.Description = override.Description
			}
			if override.Annotations != nil {
				tool.Annotations = override.Annotations
			}
		}

		def, err := json.Marshal(tool)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal tool definition: %w", err)
		}

		// Determine final name: override rename > prefix_name > name
		finalName := tool.Name
		if override, ok := server.ToolOverrides[tool.Name]; ok && override.Rename != "" {
			finalName = override.Rename
		} else if server.Prefix != "" {
			finalName = server.Prefix + "_" + tool.Name
		}

		tools = append(tools, &FederatedTool{
			Name:       finalName,
			Server:     server.URL,
			Prefix:     server.Prefix,
			Definition: def,
		})
	}

	return tools, nil
}

// GetTool returns a federated tool by its prefixed name.
func (f *Federation) GetTool(name string) (*FederatedTool, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	tool, ok := f.tools[name]
	return tool, ok
}

// ListTools returns all discovered federated tools.
func (f *Federation) ListTools() []*FederatedTool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	tools := make([]*FederatedTool, 0, len(f.tools))
	for _, tool := range f.tools {
		tools = append(tools, tool)
	}
	return tools
}

// jsonReader returns a reader from JSON bytes.
func jsonReader(data []byte) io.Reader {
	return io.NopCloser(readerFromBytes(data))
}

type bytesReader struct {
	data []byte
	pos  int
}

func readerFromBytes(data []byte) *bytesReader {
	return &bytesReader{data: data}
}

func (r *bytesReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
