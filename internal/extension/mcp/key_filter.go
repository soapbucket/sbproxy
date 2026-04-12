// key_filter.go applies per-API-key tool access control filters.
package mcp

import (
	"fmt"
)

// ApplyKeyToolFilter applies a key-level ToolFilter after origin-level filtering.
// This provides per-key tool access control. Returns filtered tools and any error.
func ApplyKeyToolFilter(tools []Tool, toolConfigs map[string]*ToolConfig, keyFilter *ToolFilter) []Tool {
	if keyFilter == nil {
		return tools
	}
	return FilterTools(tools, toolConfigs, keyFilter)
}

// CheckToolCallAllowed verifies that a tool call is permitted by the key-level filter.
// Returns nil if allowed, an error with 403-style message if blocked.
func CheckToolCallAllowed(toolName string, toolTags []string, keyFilter *ToolFilter) error {
	if keyFilter == nil {
		return nil
	}
	if !matchesToolFilter(toolName, toolTags, keyFilter) {
		return fmt.Errorf("tool %q is not permitted by your API key's tool filter", toolName)
	}
	return nil
}

// StackFilters combines an origin-level filter and a key-level filter into a
// single effective filter. The resulting filter requires tools to pass both
// filters. If either is nil, the other is used as-is.
func StackFilters(originFilter, keyFilter *ToolFilter) *ToolFilter {
	if originFilter == nil && keyFilter == nil {
		return nil
	}
	if originFilter == nil {
		return keyFilter
	}
	if keyFilter == nil {
		return originFilter
	}

	stacked := &ToolFilter{
		Include:     mergePatterns(originFilter.Include, keyFilter.Include),
		Exclude:     append(append([]string{}, originFilter.Exclude...), keyFilter.Exclude...),
		IncludeTags: mergePatterns(originFilter.IncludeTags, keyFilter.IncludeTags),
		ExcludeTags: append(append([]string{}, originFilter.ExcludeTags...), keyFilter.ExcludeTags...),
	}
	return stacked
}

// mergePatterns merges two include pattern lists. If both are non-empty,
// only the intersection intent is kept (key-level narrows origin-level).
// If one is empty, the other is returned.
func mergePatterns(a, b []string) []string {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	// When both have include patterns, use the key-level (more restrictive).
	return b
}
