// filter.go implements glob-based include/exclude filtering for MCP tools.
package mcp

import (
	"path"
)

// matchesToolFilter checks if a tool name passes the include/exclude glob filters.
// tags are optional and used for tag-based filtering.
func matchesToolFilter(name string, tags []string, filter *ToolFilter) bool {
	if filter == nil {
		return true
	}

	// Include patterns: if set, tool must match at least one
	if len(filter.Include) > 0 {
		matched := false
		for _, pattern := range filter.Include {
			if ok, _ := path.Match(pattern, name); ok {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Exclude patterns: if any match, tool is removed
	for _, pattern := range filter.Exclude {
		if ok, _ := path.Match(pattern, name); ok {
			return false
		}
	}

	// Include tags: if set, tool must have at least one matching tag
	if len(filter.IncludeTags) > 0 {
		if !hasAnyTag(tags, filter.IncludeTags) {
			return false
		}
	}

	// Exclude tags: if tool has any matching tag, it is removed
	if len(filter.ExcludeTags) > 0 {
		if hasAnyTag(tags, filter.ExcludeTags) {
			return false
		}
	}

	return true
}

// hasAnyTag returns true if any of the tool tags match any of the filter tags.
func hasAnyTag(toolTags []string, filterTags []string) bool {
	for _, ft := range filterTags {
		for _, tt := range toolTags {
			if tt == ft {
				return true
			}
		}
	}
	return false
}

// FilterTools applies a ToolFilter to a list of Tool definitions.
// This is used for filtering tools/list responses.
func FilterTools(tools []Tool, toolConfigs map[string]*ToolConfig, filter *ToolFilter) []Tool {
	if filter == nil {
		return tools
	}

	var result []Tool
	for _, tool := range tools {
		var tags []string
		if tc, ok := toolConfigs[tool.Name]; ok {
			tags = tc.Tags
		}
		if matchesToolFilter(tool.Name, tags, filter) {
			result = append(result, tool)
		}
	}
	if result == nil {
		result = []Tool{}
	}
	return result
}
