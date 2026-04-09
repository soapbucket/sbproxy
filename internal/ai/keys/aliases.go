// Package keys provides AI virtual key management for multi-tenant access control.
package keys

// ModelAliases holds per-key model alias mappings. When a request uses a virtual
// key, the requested model name is resolved through this map before routing.
// This enables teams to use stable alias names (e.g., "fast", "smart") that map
// to different underlying models per key, without changing client code.
//
// Example: key A maps "fast" -> "gpt-4o-mini", key B maps "fast" -> "claude-3-haiku".
type ModelAliases map[string]string

// ResolveModelAlias resolves a model name through the virtual key's alias map.
// If the key has no aliases or the requested model has no alias, the original
// model name is returned unchanged.
func ResolveModelAlias(key *VirtualKey, requestedModel string) string {
	if key == nil || len(key.ModelAliases) == 0 {
		return requestedModel
	}
	if alias, ok := key.ModelAliases[requestedModel]; ok && alias != "" {
		return alias
	}
	return requestedModel
}
