package mcp

import (
	"encoding/json"
	"testing"
)

func makeToolConfigs(names []string, tags map[string][]string) map[string]*ToolConfig {
	configs := make(map[string]*ToolConfig, len(names))
	for _, name := range names {
		tc := &ToolConfig{
			Name:        name,
			Description: "test tool",
			InputSchema: json.RawMessage(`{}`),
		}
		if t, ok := tags[name]; ok {
			tc.Tags = t
		}
		configs[name] = tc
	}
	return configs
}

func makeTools(names []string) []Tool {
	tools := make([]Tool, len(names))
	for i, name := range names {
		tools[i] = Tool{Name: name, InputSchema: json.RawMessage(`{}`)}
	}
	return tools
}

func TestApplyKeyToolFilter_IncludeByName(t *testing.T) {
	names := []string{"search", "write", "delete"}
	tools := makeTools(names)
	configs := makeToolConfigs(names, nil)

	filter := &ToolFilter{Include: []string{"search"}}
	result := ApplyKeyToolFilter(tools, configs, filter)

	if len(result) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(result))
	}
	if result[0].Name != "search" {
		t.Errorf("expected 'search', got %q", result[0].Name)
	}
}

func TestApplyKeyToolFilter_ExcludeByName(t *testing.T) {
	names := []string{"search", "write", "delete"}
	tools := makeTools(names)
	configs := makeToolConfigs(names, nil)

	filter := &ToolFilter{Exclude: []string{"delete"}}
	result := ApplyKeyToolFilter(tools, configs, filter)

	if len(result) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(result))
	}
	for _, tool := range result {
		if tool.Name == "delete" {
			t.Error("delete should have been filtered out")
		}
	}
}

func TestCheckToolCallAllowed_Blocked(t *testing.T) {
	filter := &ToolFilter{Include: []string{"read_*"}}

	err := CheckToolCallAllowed("delete_file", nil, filter)
	if err == nil {
		t.Fatal("expected error for blocked tool call")
	}

	// Allowed tool should pass.
	err = CheckToolCallAllowed("read_data", nil, filter)
	if err != nil {
		t.Errorf("expected nil for allowed tool, got %v", err)
	}
}

func TestCheckToolCallAllowed_NilFilter(t *testing.T) {
	err := CheckToolCallAllowed("anything", nil, nil)
	if err != nil {
		t.Errorf("nil filter should allow all, got %v", err)
	}
}

func TestStackFilters_CombinesExcludes(t *testing.T) {
	origin := &ToolFilter{Exclude: []string{"admin_*"}}
	key := &ToolFilter{Exclude: []string{"debug_*"}}

	stacked := StackFilters(origin, key)
	if stacked == nil {
		t.Fatal("expected non-nil stacked filter")
	}
	if len(stacked.Exclude) != 2 {
		t.Errorf("expected 2 exclude patterns, got %d", len(stacked.Exclude))
	}
}

func TestStackFilters_NilOrigin(t *testing.T) {
	key := &ToolFilter{Include: []string{"read_*"}}
	stacked := StackFilters(nil, key)
	if stacked != key {
		t.Error("expected key filter when origin is nil")
	}
}

func TestStackFilters_NilKey(t *testing.T) {
	origin := &ToolFilter{Include: []string{"*"}}
	stacked := StackFilters(origin, nil)
	if stacked != origin {
		t.Error("expected origin filter when key is nil")
	}
}

func TestStackFilters_BothNil(t *testing.T) {
	if StackFilters(nil, nil) != nil {
		t.Error("expected nil when both are nil")
	}
}

func TestStackFilters_KeyNarrowsIncludes(t *testing.T) {
	origin := &ToolFilter{Include: []string{"*"}}
	key := &ToolFilter{Include: []string{"search_*"}}

	stacked := StackFilters(origin, key)
	// Key-level includes should take precedence (more restrictive).
	if len(stacked.Include) != 1 || stacked.Include[0] != "search_*" {
		t.Errorf("expected key-level includes to take precedence, got %v", stacked.Include)
	}
}
