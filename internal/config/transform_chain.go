// transform_chain.go resolves named transform chain references at config load time.
package config

import (
	"encoding/json"
	"fmt"
)

// resolveTransformChains expands chain references in a list of raw transform
// messages. If a transform entry has a "chain" field (and no "type" field),
// it is replaced with the transforms from the named chain defined in
// TransformChains. Chain references are resolved recursively to support chains
// that reference other chains, with cycle detection to prevent infinite loops.
//
// Resolution happens at config load time so there is no runtime overhead.
func resolveTransformChains(
	transforms []json.RawMessage,
	chains map[string][]json.RawMessage,
) ([]json.RawMessage, error) {
	if len(chains) == 0 {
		return transforms, nil
	}
	visited := make(map[string]bool)
	return resolveChainList(transforms, chains, visited)
}

// resolveChainList expands chain references in a list, tracking visited chain
// names to detect cycles.
func resolveChainList(
	transforms []json.RawMessage,
	chains map[string][]json.RawMessage,
	visited map[string]bool,
) ([]json.RawMessage, error) {
	result := make([]json.RawMessage, 0, len(transforms))

	for _, raw := range transforms {
		ref, err := parseChainRef(raw)
		if err != nil {
			return nil, err
		}

		// Not a chain reference, keep the transform as-is.
		if ref == "" {
			result = append(result, raw)
			continue
		}

		// Look up the named chain.
		chainTransforms, ok := chains[ref]
		if !ok {
			return nil, fmt.Errorf("transform_chains: unknown chain %q", ref)
		}

		// Cycle detection.
		if visited[ref] {
			return nil, fmt.Errorf("transform_chains: circular reference detected for chain %q", ref)
		}
		visited[ref] = true

		// Recursively resolve the chain's transforms (they may contain nested chain refs).
		expanded, err := resolveChainList(chainTransforms, chains, visited)
		if err != nil {
			return nil, err
		}

		// Remove from visited after resolution so the same chain can be used
		// in different (non-circular) positions.
		delete(visited, ref)

		result = append(result, expanded...)
	}

	return result, nil
}

// chainRefProbe is a minimal struct used to detect chain references.
type chainRefProbe struct {
	Type  string `json:"type"`
	Chain string `json:"chain"`
}

// parseChainRef checks if a raw JSON transform is a chain reference.
// A chain reference has a "chain" field and no "type" field (or an empty type).
// Returns the chain name if it is a reference, or "" if it is a regular transform.
func parseChainRef(raw json.RawMessage) (string, error) {
	var probe chainRefProbe
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", fmt.Errorf("transform_chains: failed to parse transform entry: %w", err)
	}
	if probe.Chain == "" {
		return "", nil
	}
	if probe.Type != "" {
		// Has both type and chain, which is a configuration error.
		return "", fmt.Errorf("transform_chains: transform has both \"type\" (%q) and \"chain\" (%q); use one or the other", probe.Type, probe.Chain)
	}
	return probe.Chain, nil
}
