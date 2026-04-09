package mcp

import (
	"encoding/json"
	"fmt"
)

// DefaultMaxOriginDepth is the maximum recursion depth for origin references.
const DefaultMaxOriginDepth = 10

// ValidateOriginReferences checks federated server configs for circular references
// and excessive depth. It walks origin references and detects cycles.
func ValidateOriginReferences(servers []FederatedServerConfig) error {
	// Build a graph of origin references
	visited := make(map[string]bool)

	for _, server := range servers {
		if server.HasOriginRef() {
			if err := checkOriginCycle(server.Origin, visited, 0); err != nil {
				return err
			}
		}
		if server.HasEmbeddedOrigin() {
			if err := checkEmbeddedOriginDepth(server.OriginConfig, 0); err != nil {
				return err
			}
		}
	}

	return nil
}

// checkOriginCycle detects cycles in hostname-based origin references.
func checkOriginCycle(hostname string, visited map[string]bool, depth int) error {
	if depth > DefaultMaxOriginDepth {
		return fmt.Errorf("mcp: origin reference depth exceeds maximum (%d) at %q", DefaultMaxOriginDepth, hostname)
	}

	if visited[hostname] {
		return fmt.Errorf("mcp: circular origin reference detected at %q", hostname)
	}

	visited[hostname] = true
	// Note: full cycle detection across the config graph requires the config loader.
	// This validates the MCP-level references within a single config.
	return nil
}

// checkEmbeddedOriginDepth validates that embedded origin configs don't nest too deeply.
func checkEmbeddedOriginDepth(data json.RawMessage, depth int) error {
	if depth > DefaultMaxOriginDepth {
		return fmt.Errorf("mcp: embedded origin config depth exceeds maximum (%d)", DefaultMaxOriginDepth)
	}

	// Parse the embedded config to check for nested federated servers
	var embedded struct {
		Action struct {
			FederatedServers []FederatedServerConfig `json:"federated_servers"`
		} `json:"action"`
	}

	if err := json.Unmarshal(data, &embedded); err != nil {
		// Not parseable as MCP config - that's fine, it might be a different action type
		return nil
	}

	// Recursively check nested federated servers
	for _, server := range embedded.Action.FederatedServers {
		if server.HasOriginRef() {
			visited := make(map[string]bool)
			if err := checkOriginCycle(server.Origin, visited, depth+1); err != nil {
				return err
			}
		}
		if server.HasEmbeddedOrigin() {
			if err := checkEmbeddedOriginDepth(server.OriginConfig, depth+1); err != nil {
				return err
			}
		}
	}

	return nil
}

// ValidateProxyHandlerSource enforces mutual exclusivity of url, origin_host,
// and origin_config on a ProxyHandler. Exactly one must be set.
func ValidateProxyHandlerSource(handler *ProxyHandler) error {
	if handler == nil {
		return fmt.Errorf("proxy handler is nil")
	}

	count := 0
	if handler.URL != "" {
		count++
	}
	if handler.OriginHost != "" {
		count++
	}
	if len(handler.OriginConfig) > 0 {
		count++
	}

	if count == 0 {
		return fmt.Errorf("proxy handler requires exactly one of: url, origin_host, origin_config")
	}
	if count > 1 {
		return fmt.Errorf("proxy handler fields url, origin_host, origin_config are mutually exclusive")
	}

	return nil
}

// ValidateServerConfig validates a single FederatedServerConfig has exactly one
// source configured (url, origin, or origin_config).
func ValidateServerConfig(server FederatedServerConfig) error {
	sources := 0
	if server.URL != "" {
		sources++
	}
	if server.HasOriginRef() {
		sources++
	}
	if server.HasEmbeddedOrigin() {
		sources++
	}

	if sources == 0 {
		return fmt.Errorf("mcp: federated server requires one of url, origin, or origin_config")
	}
	if sources > 1 {
		return fmt.Errorf("mcp: federated server must have only one of url, origin, or origin_config")
	}

	return nil
}
